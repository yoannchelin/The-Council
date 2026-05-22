// Package report builds the final assessment from scored zones.
package report

import (
	"fmt"
	"slices"
	"strings"

	"github.com/yoannchl/the-council/internal/correlate"
	"github.com/yoannchl/the-council/internal/signals"
	"github.com/yoannchl/the-council/internal/store"
)

// ActionItem is a single recommended action for the developer.
type ActionItem struct {
	Rank          int
	Kind          string
	PriorityScore float64
	Signals       []string
	Qualified     string
	Path          string
	Headline      string
	Action        string
}

// Assessment is the full result of an assess_repo call.
type Assessment struct {
	HealthScore      float64
	TotalZones       int // total zones with any signal (denominator for health score)
	UnhealthyZones   int // zones with priority score >= 0.5
	AgentsPresent    []string
	MissingAgents    []string
	TopItems         []ActionItem
	ConvergenceZones []string
	SignalSummary    map[string]int
}

// Build generates the assessment from scored zones.
func Build(scored []correlate.ScoredZone, agentsPresent []string, missingAgents []string, topN int) *Assessment {
	a := &Assessment{
		AgentsPresent: agentsPresent,
		MissingAgents: missingAgents,
		SignalSummary: make(map[string]int),
	}

	conv := correlate.ConvergenceZones(scored)
	for _, z := range conv {
		label := z.Path
		if z.Qualified != "" {
			label = z.Qualified
		}
		a.ConvergenceZones = append(a.ConvergenceZones, label)
	}

	limit := topN
	if limit > len(scored) {
		limit = len(scored)
	}
	for i, sz := range scored[:limit] {
		item := buildItem(i+1, sz)
		a.TopItems = append(a.TopItems, item)
		for _, sig := range item.Signals {
			a.SignalSummary[sig]++
		}
	}

	a.HealthScore, a.TotalZones, a.UnhealthyZones = computeHealth(scored)
	return a
}

func buildItem(rank int, sz correlate.ScoredZone) ActionItem {
	z := sz.Zone
	var sigs []string
	var parts []string
	kind := "investigate_coupling"

	if z.BlastScore > 0.4 {
		sigs = append(sigs, "blast")
		// Show both the normalised score and the actual direct fan-in count.
		parts = append(parts, fmt.Sprintf("blast score %.0f/100 (fan-in %d)", z.BlastScore*100, z.BlastFanIn))
	}
	if z.SentinelGap > 0.6 {
		sigs = append(sigs, "sentinel")
		if z.SentinelGap >= 0.95 {
			parts = append(parts, "no test coverage")
			kind = "fix_untested_critical"
		} else {
			parts = append(parts, fmt.Sprintf("low test coverage (gap %.0f%%)", z.SentinelGap*100))
			kind = "add_coverage"
		}
	}
	if z.HunterScore > 0.3 {
		sigs = append(sigs, "hunter")
		if z.HunterFixes > 0 {
			parts = append(parts, fmt.Sprintf("%d bug-fix commits", z.HunterFixes))
		} else {
			parts = append(parts, "fix hotspot")
		}
		if kind != "fix_untested_critical" {
			kind = "fix_buggy_zone"
		}
	}
	if z.DepVulnScore > 0 {
		sigs = append(sigs, "dep")
		if len(z.DepVulnIDs) > 0 {
			parts = append(parts, fmt.Sprintf("CVEs: %s", strings.Join(z.DepVulnIDs, ", ")))
			kind = "patch_vulnerability"
		}
		if z.DepAbandoned {
			parts = append(parts, "abandoned module")
			kind = "replace_abandoned"
		}
		if z.DepBadLicense {
			parts = append(parts, fmt.Sprintf("license issue (%s)", z.DepLicense))
			if kind == "investigate_coupling" {
				kind = "review_license"
			}
		}
	}
	if z.ChurnScore > 0.5 {
		sigs = append(sigs, "archaeo")
		parts = append(parts, fmt.Sprintf("high churn (%.0f%%)", z.ChurnScore*100))
	}
	if z.CouplingScore > 0.3 {
		sigs = append(sigs, "coupling")
		parts = append(parts, fmt.Sprintf("implicit coupling with %s", z.CouplingWith))
	}

	target := z.Path
	if z.Qualified != "" {
		target = z.Qualified
	}

	headline := fmt.Sprintf("%s — %s [score %.0f]",
		target, strings.Join(parts, ", "), sz.PriorityScore*100)

	return ActionItem{
		Rank:          rank,
		Kind:          kind,
		PriorityScore: sz.PriorityScore,
		Signals:       sigs,
		Qualified:     z.Qualified,
		Path:          z.Path,
		Headline:      headline,
		Action:        actionText(kind, z),
	}
}

func actionText(kind string, z *signals.Zone) string {
	switch kind {
	case "fix_untested_critical":
		return fmt.Sprintf("Write tests for %s — high blast radius, zero direct tests.", z.Path)
	case "fix_buggy_zone":
		if z.HunterFixes > 0 {
			return fmt.Sprintf("Review %s for recurring error patterns (%d bug-fix commits).", z.Path, z.HunterFixes)
		}
		return fmt.Sprintf("Review %s — flagged as a fix hotspot by hunter (high blast risk in recent fix commits).", z.Path)
	case "patch_vulnerability":
		return fmt.Sprintf("Patch CVEs in dependencies: %s", strings.Join(z.DepVulnIDs, ", "))
	case "replace_abandoned":
		return fmt.Sprintf("Replace abandoned module %s with a maintained alternative.", z.Path)
	case "review_license":
		return fmt.Sprintf("Review license compatibility for %s (license: %s).", z.Path, z.DepLicense)
	case "add_coverage":
		return fmt.Sprintf("Increase test coverage for %s.", z.Path)
	case "investigate_coupling":
		if z.CouplingWith != "" {
			return fmt.Sprintf("Investigate hidden coupling: %s co-changes frequently with %s without an explicit dependency.", z.Path, z.CouplingWith)
		}
		return fmt.Sprintf("Investigate coupling or hidden dependency in %s.", z.Path)
	default:
		return fmt.Sprintf("Investigate coupling or hidden dependency in %s.", z.Path)
	}
}

// computeHealth returns a 0-100 score representing the overall risk level
// across all assessed zones.
//
// Formula: 100 × (1 − avgScore), where avgScore is the mean priority score
// across every zone (not just the top N). This ensures the score reflects
// breadth of risk, not just the intensity of the worst few zones.
// unhealthy counts zones with priority >= 0.5 for context.
func computeHealth(scored []correlate.ScoredZone) (health float64, total, unhealthy int) {
	total = len(scored)
	if total == 0 {
		return 100.0, 0, 0
	}
	var sum float64
	for _, s := range scored {
		sum += s.PriorityScore
		if s.PriorityScore >= 0.5 {
			unhealthy++
		}
	}
	h := 100.0 * (1.0 - sum/float64(total))
	if h < 0 {
		h = 0
	}
	return h, total, unhealthy
}

// ToStoreItems converts report ActionItems to store ActionItems for persistence.
func ToStoreItems(assessmentID int64, items []ActionItem) []store.ActionItem {
	out := make([]store.ActionItem, len(items))
	for i, it := range items {
		out[i] = store.ActionItem{
			AssessmentID:  assessmentID,
			Rank:          it.Rank,
			Kind:          it.Kind,
			PriorityScore: it.PriorityScore,
			Signals:       it.Signals,
			Qualified:     it.Qualified,
			Path:          it.Path,
			Headline:      it.Headline,
			Action:        it.Action,
		}
	}
	return out
}

// FormatText renders the assessment as a human-readable text report.
func FormatText(a *Assessment, repoPath string) string {
	var sb strings.Builder

	fmt.Fprintf(&sb, "Council Assessment\n")
	fmt.Fprintf(&sb, "Repo: %s\n", repoPath)
	fmt.Fprintf(&sb, "Health score: %.1f/100 (%d/%d zones at risk)\n", a.HealthScore, a.UnhealthyZones, a.TotalZones)

	var agentParts []string
	for _, ag := range []string{"archaeo", "blast", "sentinel", "hunter", "dep"} {
		mark := "✗"
		if slices.Contains(a.AgentsPresent, ag) {
			mark = "✓"
		}
		agentParts = append(agentParts, ag+" "+mark)
	}
	fmt.Fprintf(&sb, "Agents: %s\n", strings.Join(agentParts, ", "))
	if len(a.MissingAgents) > 0 {
		fmt.Fprintf(&sb, "Missing signals: %s\n", strings.Join(a.MissingAgents, ", "))
	}
	sb.WriteString("\n")

	fmt.Fprintf(&sb, "TOP %d ACTION ITEMS\n\n", len(a.TopItems))
	for _, it := range a.TopItems {
		fmt.Fprintf(&sb, "%d. [score %.0f] %s\n", it.Rank, it.PriorityScore*100, strings.ToUpper(it.Kind))
		fmt.Fprintf(&sb, "   %s\n", it.Headline)
		fmt.Fprintf(&sb, "   Action: %s\n\n", it.Action)
	}

	if len(a.ConvergenceZones) > 0 {
		sb.WriteString("CONVERGENCE ZONES (3+ signals)\n")
		for _, z := range a.ConvergenceZones {
			fmt.Fprintf(&sb, "  %s\n", z)
		}
	}

	return sb.String()
}

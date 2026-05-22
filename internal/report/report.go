// Package report builds the final assessment from scored zones.
package report

import (
	"fmt"
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

	// Convergence zones
	conv := correlate.ConvergenceZones(scored)
	for _, z := range conv {
		label := z.Path
		if z.Qualified != "" {
			label = z.Qualified
		}
		a.ConvergenceZones = append(a.ConvergenceZones, label)
	}

	// Build action items
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

	// Health score: 100 minus the average priority of top 10 (scaled to 100)
	a.HealthScore = computeHealth(scored)

	return a
}

func buildItem(rank int, sz correlate.ScoredZone) ActionItem {
	z := sz.Zone
	var sigs []string
	var parts []string

	kind := "investigate_coupling"

	if z.BlastScore > 0.4 {
		sigs = append(sigs, "blast")
		parts = append(parts, fmt.Sprintf("blast radius %.0f", z.BlastScore*100))
	}
	if z.SentinelGap > 0.6 {
		sigs = append(sigs, "sentinel")
		if z.SentinelGap == 1.0 {
			parts = append(parts, "0 tests")
			kind = "fix_untested_critical"
		} else {
			parts = append(parts, "low test coverage")
			kind = "add_coverage"
		}
	}
	if z.HunterScore > 0.3 {
		sigs = append(sigs, "hunter")
		parts = append(parts, fmt.Sprintf("%d bug fixes", z.HunterBugFixes))
		if kind != "fix_untested_critical" {
			kind = "fix_buggy_zone"
		}
	}
	if z.DepVulnScore > 0 {
		sigs = append(sigs, "dep")
		parts = append(parts, fmt.Sprintf("CVEs: %s", strings.Join(z.DepVulnIDs, ", ")))
		kind = "patch_vulnerability"
	}

	target := z.Path
	if z.Qualified != "" {
		target = z.Qualified
	}

	headline := fmt.Sprintf("%s — %s [score %.0f]",
		target, strings.Join(parts, ", "), sz.PriorityScore*100)

	action := actionText(kind, z)

	return ActionItem{
		Rank:          rank,
		Kind:          kind,
		PriorityScore: sz.PriorityScore,
		Signals:       sigs,
		Qualified:     z.Qualified,
		Path:          z.Path,
		Headline:      headline,
		Action:        action,
	}
}

func actionText(kind string, z *signals.Zone) string {
	switch kind {
	case "fix_untested_critical":
		return fmt.Sprintf("Write tests for %s — it has high blast radius with zero direct tests.", z.Path)
	case "fix_buggy_zone":
		return fmt.Sprintf("Review %s for recurring error patterns (%d bug-fix commits).", z.Path, z.HunterBugFixes)
	case "patch_vulnerability":
		return fmt.Sprintf("Patch dependencies with CVEs: %s", strings.Join(z.DepVulnIDs, ", "))
	case "add_coverage":
		return fmt.Sprintf("Increase test coverage for %s.", z.Path)
	default:
		return fmt.Sprintf("Investigate coupling or hidden dependency in %s.", z.Path)
	}
}

func computeHealth(scored []correlate.ScoredZone) float64 {
	if len(scored) == 0 {
		return 100.0
	}
	top := scored
	if len(top) > 10 {
		top = top[:10]
	}
	var sum float64
	for _, s := range top {
		sum += s.PriorityScore
	}
	avg := sum / float64(len(top))
	health := 100.0 * (1.0 - avg)
	if health < 0 {
		health = 0
	}
	return health
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

	sb.WriteString("Council Assessment\n")
	sb.WriteString(fmt.Sprintf("Repo: %s\n", repoPath))
	sb.WriteString(fmt.Sprintf("Health score: %.0f/100\n", a.HealthScore))

	// Agents line
	var agentParts []string
	for _, ag := range []string{"archaeo", "blast", "sentinel", "hunter", "dep"} {
		mark := "✗"
		for _, p := range a.AgentsPresent {
			if p == ag {
				mark = "✓"
				break
			}
		}
		agentParts = append(agentParts, ag+" "+mark)
	}
	sb.WriteString(fmt.Sprintf("Agents: %s\n", strings.Join(agentParts, ", ")))
	if len(a.MissingAgents) > 0 {
		sb.WriteString(fmt.Sprintf("Missing signals: %s\n", strings.Join(a.MissingAgents, ", ")))
	}
	sb.WriteString("\n")

	sb.WriteString(fmt.Sprintf("TOP %d ACTION ITEMS\n\n", len(a.TopItems)))
	for _, it := range a.TopItems {
		sb.WriteString(fmt.Sprintf("%d. [score %.0f] %s\n", it.Rank, it.PriorityScore*100, strings.ToUpper(it.Kind)))
		sb.WriteString(fmt.Sprintf("   %s\n", it.Headline))
		sb.WriteString(fmt.Sprintf("   Action: %s\n\n", it.Action))
	}

	if len(a.ConvergenceZones) > 0 {
		sb.WriteString("CONVERGENCE ZONES (3+ signals)\n")
		for _, z := range a.ConvergenceZones {
			sb.WriteString(fmt.Sprintf("  %s\n", z))
		}
	}

	return sb.String()
}

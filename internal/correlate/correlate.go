// Package correlate computes composite priority scores and identifies convergence zones.
package correlate

import (
	"sort"
	"strings"

	"github.com/yoannchl/the-council/internal/signals"
)

// ScoredZone is a Zone with its composite priority score.
type ScoredZone struct {
	*signals.Zone
	PriorityScore float64
}

// Score computes the composite priority for a single zone.
// Missing signals (score == -1) are treated as 0 contribution.
func Score(z *signals.Zone) float64 {
	blast := max0(z.BlastScore)
	sentinel := max0(z.SentinelGap)
	hunter := max0(z.HunterScore)
	dep := max0(z.DepVulnScore)
	churn := max0(z.ChurnScore)
	coupling := max0(z.CouplingScore)

	score := blast*Weights.Blast +
		sentinel*Weights.Sentinel +
		hunter*Weights.Hunter +
		dep*Weights.Dep +
		churn*Weights.Churn +
		coupling*Weights.Coupling

	if z.SignalCount >= ConvergenceThreshold {
		score *= Weights.Convergence
	}

	// Cap at 1.0
	if score > 1.0 {
		score = 1.0
	}
	return score
}

// Rank takes all zones, scores them, filters below minPriority and by skipPaths,
// and returns them sorted by descending priority.
// skipPaths is a list of path prefixes to exclude (e.g. "test/", "vendor/").
func Rank(zones map[string]*signals.Zone, minPriority float64, skipPaths []string) []ScoredZone {
	out := make([]ScoredZone, 0, len(zones))
	for _, z := range zones {
		if hasPrefix(z.Path, skipPaths) {
			continue
		}
		s := Score(z)
		if s < minPriority {
			continue
		}
		out = append(out, ScoredZone{Zone: z, PriorityScore: s})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].PriorityScore != out[j].PriorityScore {
			return out[i].PriorityScore > out[j].PriorityScore
		}
		// Stable tie-break: higher fan-in first, then alphabetical by qualified name.
		if out[i].BlastFanIn != out[j].BlastFanIn {
			return out[i].BlastFanIn > out[j].BlastFanIn
		}
		return out[i].Qualified < out[j].Qualified
	})
	return out
}

func hasPrefix(path string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// ConvergenceZones returns zones where 3+ signals converge.
func ConvergenceZones(scored []ScoredZone) []ScoredZone {
	var out []ScoredZone
	for _, z := range scored {
		if z.SignalCount >= ConvergenceThreshold {
			out = append(out, z)
		}
	}
	return out
}

func max0(v float64) float64 {
	if v < 0 {
		return 0
	}
	return v
}

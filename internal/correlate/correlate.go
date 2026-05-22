// Package correlate computes composite priority scores and identifies convergence zones.
package correlate

import (
	"sort"

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

	score := blast*Weights.Blast +
		sentinel*Weights.Sentinel +
		hunter*Weights.Hunter +
		dep*Weights.Dep +
		churn*Weights.Churn

	if z.SignalCount >= ConvergenceThreshold {
		score *= Weights.Convergence
	}

	// Cap at 1.0
	if score > 1.0 {
		score = 1.0
	}
	return score
}

// Rank takes all zones, scores them, filters below minPriority, and returns
// them sorted by descending priority.
func Rank(zones map[string]*signals.Zone, minPriority float64) []ScoredZone {
	out := make([]ScoredZone, 0, len(zones))
	for _, z := range zones {
		s := Score(z)
		if s < minPriority {
			continue
		}
		out = append(out, ScoredZone{Zone: z, PriorityScore: s})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].PriorityScore > out[j].PriorityScore
	})
	return out
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

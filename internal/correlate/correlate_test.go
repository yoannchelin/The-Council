package correlate

import (
	"testing"

	"github.com/yoannchl/the-council/internal/signals"
)

func zone(blast, sentinel, hunter, dep, churn float64) *signals.Zone {
	signalCount := 0
	if blast >= 0 {
		signalCount++
	}
	if sentinel >= 0 {
		signalCount++
	}
	if hunter >= 0 {
		signalCount++
	}
	if dep >= 0 {
		signalCount++
	}
	if churn >= 0 {
		signalCount++
	}
	return &signals.Zone{
		Path:         "internal/foo/bar.go",
		BlastScore:   blast,
		SentinelGap:  sentinel,
		HunterScore:  hunter,
		DepVulnScore: dep,
		ChurnScore:   churn,
		SignalCount:  signalCount,
	}
}

func TestScore_AllSignals(t *testing.T) {
	z := zone(0.8, 0.8, 0.8, 0.8, 0.8)
	s := Score(z)
	// 5 signals → convergence bonus, capped at 1.0
	if s != 1.0 {
		t.Errorf("expected 1.0 (capped), got %f", s)
	}
}

func TestScore_NoConvergence(t *testing.T) {
	// 2 signals — no convergence bonus
	z := zone(1.0, 1.0, -1, -1, -1)
	s := Score(z)
	expected := 1.0*Weights.Blast + 1.0*Weights.Sentinel
	if abs(s-expected) > 1e-9 {
		t.Errorf("expected %f, got %f", expected, s)
	}
}

func TestScore_MissingSignalsTreatedAsZero(t *testing.T) {
	// absent signals (-1) must not reduce the score
	z := zone(1.0, -1, -1, -1, -1)
	s := Score(z)
	expected := 1.0 * Weights.Blast
	if abs(s-expected) > 1e-9 {
		t.Errorf("expected %f, got %f", expected, s)
	}
}

func TestScore_ConvergenceBonus(t *testing.T) {
	// Exactly 3 signals at moderate value — must get ×1.5
	z := zone(0.4, 0.4, 0.4, -1, -1)
	withoutBonus := 0.4*Weights.Blast + 0.4*Weights.Sentinel + 0.4*Weights.Hunter
	withBonus := withoutBonus * Weights.Convergence
	s := Score(z)
	if abs(s-withBonus) > 1e-9 {
		t.Errorf("expected %f (with convergence), got %f", withBonus, s)
	}
}

func TestScore_CappedAtOne(t *testing.T) {
	z := zone(1, 1, 1, 1, 1)
	if Score(z) != 1.0 {
		t.Error("score should be capped at 1.0")
	}
}

func TestRank_Sorted(t *testing.T) {
	zones := map[string]*signals.Zone{
		"a": zone(0.2, -1, -1, -1, -1),
		"b": zone(0.9, 0.9, 0.9, -1, -1),
		"c": zone(0.5, -1, -1, -1, -1),
	}
	ranked := Rank(zones, 0, nil)
	if len(ranked) != 3 {
		t.Fatalf("expected 3 results, got %d", len(ranked))
	}
	for i := 1; i < len(ranked); i++ {
		if ranked[i].PriorityScore > ranked[i-1].PriorityScore {
			t.Errorf("not sorted at index %d: %f > %f", i, ranked[i].PriorityScore, ranked[i-1].PriorityScore)
		}
	}
}

func TestRank_MinPriorityFilter(t *testing.T) {
	// "high" has 3 signals → convergence bonus, score ≈ (0.9*0.28+0.9*0.24+0.9*0.23)*1.5 ≈ 1.0 (capped)
	// "low" has 1 signal, blast=0.1 → score = 0.028, below 0.5 threshold
	zones := map[string]*signals.Zone{
		"low":  zone(0.1, -1, -1, -1, -1),
		"high": zone(0.9, 0.9, 0.9, -1, -1),
	}
	ranked := Rank(zones, 0.5, nil)
	if len(ranked) != 1 {
		t.Errorf("expected 1 result above threshold, got %d", len(ranked))
	}
}

func TestRank_SkipPaths(t *testing.T) {
	zones := map[string]*signals.Zone{
		"a": {Path: "test/e2e/framework/log.go",  BlastScore: 0.9, SentinelGap: 1.0, HunterScore: -1, DepVulnScore: -1, ChurnScore: -1, SignalCount: 2},
		"b": {Path: "pkg/apis/core/validation.go", BlastScore: 0.8, SentinelGap: 1.0, HunterScore: -1, DepVulnScore: -1, ChurnScore: -1, SignalCount: 2},
	}
	ranked := Rank(zones, 0, []string{"test/"})
	if len(ranked) != 1 {
		t.Fatalf("expected 1 result (test/ excluded), got %d", len(ranked))
	}
	if ranked[0].Path != "pkg/apis/core/validation.go" {
		t.Errorf("wrong zone returned: %q", ranked[0].Path)
	}
}

func TestRank_SkipPaths_MultiplePrefix(t *testing.T) {
	zones := map[string]*signals.Zone{
		"a": {Path: "test/e2e/log.go",    BlastScore: 0.9, SignalCount: 1},
		"b": {Path: "vendor/foo/bar.go",  BlastScore: 0.8, SignalCount: 1},
		"c": {Path: "pkg/real/code.go",   BlastScore: 0.7, SignalCount: 1},
	}
	ranked := Rank(zones, 0, []string{"test/", "vendor/"})
	if len(ranked) != 1 || ranked[0].Path != "pkg/real/code.go" {
		t.Errorf("expected only pkg/real/code.go, got %v", ranked)
	}
}

func TestRank_Empty(t *testing.T) {
	ranked := Rank(map[string]*signals.Zone{}, 0, nil)
	if len(ranked) != 0 {
		t.Error("expected empty result")
	}
}

func TestConvergenceZones(t *testing.T) {
	ranked := []ScoredZone{
		{Zone: zone(0.5, 0.5, 0.5, -1, -1), PriorityScore: 0.8},  // 3 signals
		{Zone: zone(0.9, -1, -1, -1, -1), PriorityScore: 0.6},     // 1 signal
		{Zone: zone(0.3, 0.3, 0.3, 0.3, -1), PriorityScore: 0.5}, // 4 signals
	}
	conv := ConvergenceZones(ranked)
	if len(conv) != 2 {
		t.Errorf("expected 2 convergence zones, got %d", len(conv))
	}
}

func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}

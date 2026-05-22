package report

import (
	"strings"
	"testing"

	"github.com/yoannchl/the-council/internal/correlate"
	"github.com/yoannchl/the-council/internal/signals"
)

func scored(path string, blast, sentinel, hunter, dep, churn float64) correlate.ScoredZone {
	cnt := 0
	if blast >= 0 {
		cnt++
	}
	if sentinel >= 0 {
		cnt++
	}
	if hunter >= 0 {
		cnt++
	}
	if dep >= 0 {
		cnt++
	}
	if churn >= 0 {
		cnt++
	}
	z := &signals.Zone{
		Path:         path,
		BlastScore:   blast,
		SentinelGap:  sentinel,
		HunterScore:  hunter,
		DepVulnScore: dep,
		ChurnScore:   churn,
		HunterFixes:  5,
		SignalCount:  cnt,
	}
	return correlate.ScoredZone{Zone: z, PriorityScore: correlate.Score(z)}
}

func TestBuild_TopNRespected(t *testing.T) {
	var zones []correlate.ScoredZone
	for i := 0; i < 20; i++ {
		zones = append(zones, scored("internal/a.go", 0.5, 0.5, -1, -1, -1))
	}
	a := Build(zones, []string{"blast", "sentinel"}, nil, 5)
	if len(a.TopItems) != 5 {
		t.Errorf("expected 5 items, got %d", len(a.TopItems))
	}
}

func TestBuild_TopNLargerThanZones(t *testing.T) {
	zones := []correlate.ScoredZone{
		scored("a.go", 0.8, -1, -1, -1, -1),
		scored("b.go", 0.6, -1, -1, -1, -1),
	}
	a := Build(zones, []string{"blast"}, nil, 10)
	if len(a.TopItems) != 2 {
		t.Errorf("expected 2 items, got %d", len(a.TopItems))
	}
}

func TestBuild_RanksAreSequential(t *testing.T) {
	zones := []correlate.ScoredZone{
		scored("a.go", 0.9, 0.9, 0.9, -1, -1),
		scored("b.go", 0.5, -1, -1, -1, -1),
		scored("c.go", 0.3, -1, -1, -1, -1),
	}
	a := Build(zones, []string{"blast", "sentinel", "hunter"}, nil, 10)
	for i, it := range a.TopItems {
		if it.Rank != i+1 {
			t.Errorf("item %d has rank %d", i, it.Rank)
		}
	}
}

func TestBuild_HealthScore_NoZones(t *testing.T) {
	a := Build(nil, nil, nil, 10)
	if a.HealthScore != 100.0 {
		t.Errorf("expected 100, got %f", a.HealthScore)
	}
}

func TestBuild_HealthScore_HighRisk(t *testing.T) {
	// Score close to 1.0 should drive health score close to 0.
	var zones []correlate.ScoredZone
	for i := 0; i < 10; i++ {
		zones = append(zones, scored("x.go", 1.0, 1.0, 1.0, 1.0, 1.0))
	}
	a := Build(zones, nil, nil, 10)
	if a.HealthScore > 10 {
		t.Errorf("expected near-zero health for all-critical zones, got %f", a.HealthScore)
	}
}

func TestBuild_SignalSummary(t *testing.T) {
	zones := []correlate.ScoredZone{
		scored("a.go", 0.9, 1.0, -1, -1, -1), // blast + sentinel → fix_untested_critical
	}
	a := Build(zones, []string{"blast", "sentinel"}, nil, 10)
	if a.SignalSummary["blast"] < 1 {
		t.Error("expected blast in signal summary")
	}
	if a.SignalSummary["sentinel"] < 1 {
		t.Error("expected sentinel in signal summary")
	}
}

func TestBuild_MissingAgentsPassedThrough(t *testing.T) {
	a := Build(nil, []string{"blast"}, []string{"sentinel", "hunter"}, 10)
	if len(a.MissingAgents) != 2 {
		t.Errorf("expected 2 missing agents, got %d", len(a.MissingAgents))
	}
}

func TestBuildItem_Kind_FixUntestedCritical(t *testing.T) {
	sz := scored("internal/pay.go", 0.9, 1.0, -1, -1, -1)
	item := buildItem(1, sz)
	if item.Kind != "fix_untested_critical" {
		t.Errorf("expected fix_untested_critical, got %s", item.Kind)
	}
}

func TestBuildItem_Kind_PatchVulnerability(t *testing.T) {
	z := &signals.Zone{
		Path:         "deps/golang.org/x/crypto",
		DepVulnScore: 0.9,
		DepVulnIDs:   []string{"GO-2024-1234"},
		SignalCount:  1,
	}
	sz := correlate.ScoredZone{Zone: z, PriorityScore: 0.9}
	item := buildItem(1, sz)
	if item.Kind != "patch_vulnerability" {
		t.Errorf("expected patch_vulnerability, got %s", item.Kind)
	}
	if !strings.Contains(item.Action, "GO-2024-1234") {
		t.Error("action should mention the CVE ID")
	}
}

func TestBuildItem_Kind_ReplaceAbandoned(t *testing.T) {
	z := &signals.Zone{
		Path:         "deps/old/module",
		DepVulnScore: 0.5,
		DepAbandoned: true,
		SignalCount:  1,
	}
	sz := correlate.ScoredZone{Zone: z, PriorityScore: 0.5}
	item := buildItem(1, sz)
	if item.Kind != "replace_abandoned" {
		t.Errorf("expected replace_abandoned, got %s", item.Kind)
	}
}

func TestFormatText_ContainsSections(t *testing.T) {
	zones := []correlate.ScoredZone{
		scored("internal/payment/charge.go", 0.9, 1.0, 0.8, -1, -1),
	}
	a := Build(zones, []string{"blast", "sentinel", "hunter"}, []string{"dep"}, 10)
	text := FormatText(a, "/repo")

	for _, want := range []string{
		"Council Assessment",
		"Health score:",
		"Agents:",
		"Missing signals:",
		"TOP",
		"ACTION ITEMS",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("output missing %q", want)
		}
	}
}

func TestFormatText_ConvergenceSection(t *testing.T) {
	// 3 signals → convergence zone should appear
	zones := []correlate.ScoredZone{
		scored("internal/auth/token.go", 0.8, 0.8, 0.8, -1, -1),
	}
	a := Build(zones, []string{"blast", "sentinel", "hunter"}, nil, 10)
	text := FormatText(a, "/repo")
	if !strings.Contains(text, "CONVERGENCE ZONES") {
		t.Error("expected CONVERGENCE ZONES section")
	}
}

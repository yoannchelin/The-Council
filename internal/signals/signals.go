// Package signals collects and normalises agent data into per-zone signal structs.
package signals

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/yoannchl/the-council/internal/store"
)

// Zone is a file or symbol that has at least one signal.
type Zone struct {
	Path      string
	Qualified string // may be empty if file-level only

	// Normalised scores, 0..1. -1 means the agent was absent / no data.
	BlastScore    float64
	SentinelGap   float64 // 1.0 = no tests at all, 0.0 = well tested
	HunterScore   float64 // fix_ratio normalised to 0..1
	DepVulnScore  float64 // 0..1 based on CVSS

	// Human-readable context
	BlastFanIn   int
	HunterBugFixes int
	DepVulnIDs   []string

	// How many agent signals contributed
	SignalCount int
}

// Collect gathers all signals from the store and returns a map keyed by
// normalised path (or path+"|"+qualified).
func Collect(s *store.Store, repoRoot string) (map[string]*Zone, []string, error) {
	present := s.AgentsPresent()
	zones := make(map[string]*Zone)

	key := func(path, qualified string) string {
		p := normPath(repoRoot, path)
		if qualified != "" {
			return p + "|" + qualified
		}
		return p
	}
	getOrCreate := func(path, qualified string) *Zone {
		k := key(path, qualified)
		z, ok := zones[k]
		if !ok {
			z = &Zone{
				Path:         normPath(repoRoot, path),
				Qualified:    qualified,
				BlastScore:   -1,
				SentinelGap:  -1,
				HunterScore:  -1,
				DepVulnScore: -1,
			}
			zones[k] = z
		}
		return z
	}

	var missing []string

	// ---- blast ----
	if present["blast"] {
		metrics, err := s.BlastMetrics()
		if err != nil {
			return nil, nil, fmt.Errorf("blast metrics: %w", err)
		}
		for _, m := range metrics {
			z := getOrCreate(m.Path, m.Qualified)
			z.BlastScore = clamp01(m.RiskScore / 100.0)
			z.BlastFanIn = m.FanIn
		}
	} else {
		missing = append(missing, "blast")
	}

	// ---- sentinel ----
	if present["sentinel"] {
		covs, err := s.SentinelCoverage()
		if err != nil {
			return nil, nil, fmt.Errorf("sentinel coverage: %w", err)
		}
		for _, c := range covs {
			z := getOrCreate(c.Path, c.Qualified)
			// gap: 0 tests → 1.0, many tests → 0.0 (cap at 10)
			if c.DirectTestCount == 0 {
				z.SentinelGap = 1.0
			} else {
				z.SentinelGap = clamp01(1.0 - float64(c.DirectTestCount)/10.0)
			}
		}
	} else {
		missing = append(missing, "sentinel")
	}

	// ---- hunter ----
	if present["hunter"] {
		stats, err := s.HunterFileStats()
		if err != nil {
			return nil, nil, fmt.Errorf("hunter stats: %w", err)
		}
		for _, h := range stats {
			z := getOrCreate(h.Path, "")
			z.HunterScore = clamp01(h.FixRatio)
			z.HunterBugFixes = h.BugFixes
		}
	} else {
		missing = append(missing, "hunter")
	}

	// ---- dep ----
	if present["dep"] {
		vulns, err := s.DepVulnerabilities()
		if err != nil {
			return nil, nil, fmt.Errorf("dep vulns: %w", err)
		}
		for _, v := range vulns {
			// Attach vulnerability to each file that uses the module.
			// If UsedIn is empty we create a synthetic dep-level zone.
			paths := v.UsedIn
			if len(paths) == 0 {
				paths = []string{"deps/" + v.Module}
			}
			score := clamp01(v.CVSS / 10.0)
			for _, p := range paths {
				z := getOrCreate(p, "")
				if score > z.DepVulnScore {
					z.DepVulnScore = score
				}
				z.DepVulnIDs = append(z.DepVulnIDs, v.ID)
			}
		}
	} else {
		missing = append(missing, "dep")
	}

	// Count active signals for each zone
	for _, z := range zones {
		if z.BlastScore >= 0 {
			z.SignalCount++
		}
		if z.SentinelGap >= 0 {
			z.SignalCount++
		}
		if z.HunterScore >= 0 {
			z.SignalCount++
		}
		if z.DepVulnScore >= 0 {
			z.SignalCount++
		}
	}

	return zones, missing, nil
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

func normPath(repoRoot, path string) string {
	if repoRoot == "" || !filepath.IsAbs(path) {
		return path
	}
	rel, err := filepath.Rel(repoRoot, path)
	if err != nil {
		return path
	}
	return strings.TrimPrefix(rel, "./")
}

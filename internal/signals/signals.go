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
	Qualified string // empty for file-level zones

	// Normalised scores, 0..1. -1 means the agent was absent / no data for this zone.
	BlastScore   float64
	SentinelGap  float64 // 1.0 = no tests at all, 0.0 = well tested
	HunterScore  float64 // fix_ratio normalised to 0..1
	DepVulnScore float64 // 0..1 based on CVSS
	ChurnScore   float64 // commit frequency relative to max in repo

	// Human-readable context
	BlastFanIn     int
	HunterFixes    int
	DepVulnIDs     []string
	DepAbandoned   bool   // dep_modules: is_abandoned
	DepBadLicense  bool   // dep_modules: license_ok=0
	DepLicense     string

	// How many agent signals contributed
	SignalCount int
}

// Collect gathers all signals from the store and returns a map keyed by
// normalised path (or path+"|"+qualified).
func Collect(s *store.Store, repoRoot string) (map[string]*Zone, []string, error) {
	present := s.AgentsPresent()
	zones := make(map[string]*Zone)

	normP := func(p string) string { return normPath(repoRoot, p) }

	key := func(path, qualified string) string {
		p := normP(path)
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
				Path:         normP(path),
				Qualified:    qualified,
				BlastScore:   -1,
				SentinelGap:  -1,
				HunterScore:  -1,
				DepVulnScore: -1,
				ChurnScore:   -1,
			}
			zones[k] = z
		}
		return z
	}

	var missing []string

	// ---- archaeo churn ----
	if present["archaeo"] {
		maxCommits := s.MaxCommitCount()
		churns, err := s.FileChurn()
		if err != nil {
			return nil, nil, fmt.Errorf("file churn: %w", err)
		}
		for _, c := range churns {
			z := getOrCreate(c.Path, "")
			z.ChurnScore = clamp01(float64(c.CommitCount) / float64(maxCommits))
		}
	} else {
		missing = append(missing, "archaeo")
	}

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
			// gap: 0 tests → 1.0, ≥10 tests → 0.0
			if c.DirectTests == 0 {
				z.SentinelGap = 1.0
			} else {
				z.SentinelGap = clamp01(1.0 - float64(c.DirectTests)/10.0)
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
			z.HunterFixes = h.FixCommits
		}
	} else {
		missing = append(missing, "hunter")
	}

	// ---- dep vulnerabilities ----
	if present["dep"] {
		vulns, err := s.DepVulnerabilities()
		if err != nil {
			return nil, nil, fmt.Errorf("dep vulns: %w", err)
		}
		for _, v := range vulns {
			// Dep vulnerabilities attach to a synthetic "deps/<module>" zone.
			p := "deps/" + v.Module
			z := getOrCreate(p, "")
			score := clamp01(v.CVSS / 10.0)
			if score > z.DepVulnScore {
				z.DepVulnScore = score
			}
			z.DepVulnIDs = append(z.DepVulnIDs, v.ID)
		}

		// Abandoned / bad-license modules
		mods, err := s.DepModuleProblems()
		if err != nil {
			return nil, nil, fmt.Errorf("dep modules: %w", err)
		}
		for _, m := range mods {
			p := "deps/" + m.Path
			z := getOrCreate(p, "")
			if m.IsAbandoned {
				z.DepAbandoned = true
				if z.DepVulnScore < 0 {
					z.DepVulnScore = 0.5 // moderate risk for abandoned deps
				}
			}
			if !m.LicenseOK {
				z.DepBadLicense = true
				z.DepLicense = m.License
				if z.DepVulnScore < 0 {
					z.DepVulnScore = 0.3
				}
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
		if z.ChurnScore >= 0 {
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

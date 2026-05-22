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
	SentinelGap  float64 // 1.0 = no coverage, 0.0 = well covered (1 - quality_score)
	HunterScore  float64 // fix_ratio 0..1
	DepVulnScore float64 // CVSS/10
	ChurnScore   float64 // commit frequency relative to max in repo

	// Human-readable context
	BlastFanIn    int
	HunterFixes   int
	DepVulnIDs    []string
	DepAbandoned  bool
	DepBadLicense bool
	DepLicense    string

	// How many agent signals contributed
	SignalCount int
}

// Collect gathers all signals from the store, normalises them, merges
// file-level signals into symbol-level zones, and returns the result.
func Collect(s *store.Store, repoRoot string) (map[string]*Zone, []string, error) {
	present := s.AgentsPresent()
	zones := make(map[string]*Zone)

	normP := func(p string) string { return normPath(repoRoot, p) }

	symKey := func(path, qualified string) string { return normP(path) + "|" + qualified }
	fileKey := func(path string) string { return normP(path) }

	getOrCreateSym := func(path, qualified string) *Zone {
		k := symKey(path, qualified)
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

	getOrCreateFile := func(path string) *Zone {
		k := fileKey(path)
		z, ok := zones[k]
		if !ok {
			z = &Zone{
				Path:         normP(path),
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
			z := getOrCreateFile(c.Path)
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
			z := getOrCreateSym(m.Path, m.Qualified)
			z.BlastScore = clamp01(m.RiskScore / 100.0)
			z.BlastFanIn = m.FanIn
		}
	} else {
		missing = append(missing, "blast")
	}

	// ---- sentinel coverage ----
	if present["sentinel"] {
		covs, err := s.SentinelCoverage()
		if err != nil {
			return nil, nil, fmt.Errorf("sentinel coverage: %w", err)
		}
		for _, c := range covs {
			z := getOrCreateSym(c.Path, c.Qualified)
			// Use agent-computed quality_score as the primary signal.
			// gap = 1 - quality_score: high gap means poor coverage.
			z.SentinelGap = clamp01(1.0 - c.QualityScore)
		}

		// Boost sentinel gap where critical findings exist, regardless of test count.
		if s.TableExists("sentinel_findings") {
			findings, err := s.SentinelFindingMaxRisk()
			if err == nil {
				for _, f := range findings {
					// sentinel_findings has direct path column — match to any zone on that path.
					p := normP(f.Path)
					for k, z := range zones {
						if strings.HasPrefix(k, p) && z.SentinelGap >= 0 {
							boost := clamp01(f.MaxRisk / 100.0)
							if boost > z.SentinelGap {
								z.SentinelGap = boost
							}
						}
					}
				}
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
			z := getOrCreateFile(h.Path)
			z.HunterScore = clamp01(h.FixRatio)
			z.HunterFixes = h.FixCommits
		}
	} else {
		missing = append(missing, "hunter")
	}

	// ---- dep vulnerabilities + module problems ----
	if present["dep"] {
		vulns, err := s.DepVulnerabilities()
		if err != nil {
			return nil, nil, fmt.Errorf("dep vulns: %w", err)
		}
		for _, v := range vulns {
			z := getOrCreateFile("deps/" + v.Module)
			score := clamp01(v.CVSS / 10.0)
			if score > z.DepVulnScore {
				z.DepVulnScore = score
			}
			z.DepVulnIDs = append(z.DepVulnIDs, v.ID)
		}

		mods, err := s.DepModuleProblems()
		if err != nil {
			return nil, nil, fmt.Errorf("dep modules: %w", err)
		}
		for _, m := range mods {
			z := getOrCreateFile("deps/" + m.Path)
			if m.IsAbandoned {
				z.DepAbandoned = true
				if z.DepVulnScore < 0 {
					z.DepVulnScore = 0.5
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

	// ---- merge file-level signals into symbol-level zones ----
	// Blast and sentinel work at symbol granularity; hunter and churn work at file
	// granularity. A symbol zone that has blast+sentinel data should also inherit
	// hunter+churn from its parent file so convergence is detected correctly.
	fileZones := make(map[string]*Zone) // normalised path → file-level zone
	for _, z := range zones {
		if z.Qualified == "" {
			fileZones[z.Path] = z
		}
	}

	for _, z := range zones {
		if z.Qualified == "" {
			continue // file-level zones are the source, not the target
		}
		fz, ok := fileZones[z.Path]
		if !ok {
			continue
		}
		if z.HunterScore < 0 && fz.HunterScore >= 0 {
			z.HunterScore = fz.HunterScore
			z.HunterFixes = fz.HunterFixes
		}
		if z.ChurnScore < 0 && fz.ChurnScore >= 0 {
			z.ChurnScore = fz.ChurnScore
		}
	}

	// ---- count active signals ----
	for _, z := range zones {
		z.SignalCount = 0
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

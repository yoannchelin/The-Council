package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/yoannchl/the-council/internal/correlate"
	"github.com/yoannchl/the-council/internal/report"
	"github.com/yoannchl/the-council/internal/signals"
	"github.com/yoannchl/the-council/internal/store"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	switch os.Args[1] {
	case "assess":
		cmdAssess(os.Args[2:])
	case "top":
		cmdTop(os.Args[2:])
	case "explain":
		cmdExplain(os.Args[2:])
	case "purge":
		cmdPurge(os.Args[2:])
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `council — The Council meta-agent CLI

Usage:
  council assess  --db <path> [--repo <path>] [--top <n>] [--min <score>]
                  [--skip-path <prefix>]... [--json]
  council top     --db <path> [--repo <path>] [--n <n>]
  council explain --db <path> [--repo <path>] (--path <p> | --qualified <q>)
  council purge   --db <path> --older-than <days>

Example:
  council assess --db .archaeo/index.db --repo . --skip-path test/ --skip-path vendor/`)
}

// multiFlag allows a flag to be specified multiple times.
type multiFlag []string

func (m *multiFlag) String() string  { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func openStore(dbPath string) *store.Store {
	s, err := store.Open(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot open db %s: %v\n", dbPath, err)
		os.Exit(1)
	}
	return s
}

func cmdAssess(args []string) {
	fs := flag.NewFlagSet("assess", flag.ExitOnError)
	dbPath := fs.String("db", "", "Path to SQLite database")
	repoPath := fs.String("repo", ".", "Repo root (for path normalisation)")
	topN := fs.Int("top", 10, "Number of action items")
	minPriority := fs.Float64("min", 0.0, "Minimum priority score (0..1)")
	asJSON := fs.Bool("json", false, "Output JSON instead of text")
	var skipPaths multiFlag
	fs.Var(&skipPaths, "skip-path", "Path prefix to exclude (repeatable, e.g. --skip-path test/)")
	fs.Parse(args)

	if *dbPath == "" {
		fmt.Fprintln(os.Stderr, "error: --db is required")
		os.Exit(1)
	}

	s := openStore(*dbPath)
	defer s.Close()

	zones, missing, err := signals.Collect(s, *repoPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error collecting signals: %v\n", err)
		os.Exit(1)
	}

	scored := correlate.Rank(zones, *minPriority, skipPaths)
	present := agentNames(s.AgentsPresent())
	a := report.Build(scored, present, missing, *topN)

	summary := map[string]any{
		"total_zones":       len(zones),
		"scored_zones":      len(scored),
		"convergence_zones": len(a.ConvergenceZones),
	}
	assessRec := &store.Assessment{
		RepoPath:      *repoPath,
		AgentsPresent: present,
		Summary:       summary,
		HealthScore:   a.HealthScore,
	}
	assessID, err := s.SaveAssessment(assessRec)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not save assessment: %v\n", err)
	} else {
		s.SaveActionItems(report.ToStoreItems(assessID, a.TopItems))
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(map[string]any{
			"health_score":      a.HealthScore,
			"agents_present":    a.AgentsPresent,
			"missing_agents":    a.MissingAgents,
			"top_action_items":  a.TopItems,
			"signal_summary":    a.SignalSummary,
			"convergence_zones": a.ConvergenceZones,
		})
		return
	}

	fmt.Print(report.FormatText(a, *repoPath))
}

func cmdTop(args []string) {
	fs := flag.NewFlagSet("top", flag.ExitOnError)
	dbPath := fs.String("db", "", "Path to SQLite database")
	repoPath := fs.String("repo", ".", "Repo root")
	n := fs.Int("n", 5, "Number of items to show")
	fs.Parse(args)

	if *dbPath == "" {
		fmt.Fprintln(os.Stderr, "error: --db is required")
		os.Exit(1)
	}

	s := openStore(*dbPath)
	defer s.Close()

	assessID, err := s.LatestAssessmentID(*repoPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "no assessment found — run 'council assess' first")
		os.Exit(1)
	}

	items, err := s.LoadActionItems(assessID, *n)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	for _, it := range items {
		fmt.Printf("%d. [%.0f] %s\n   %s\n   Action: %s\n\n",
			it.Rank, it.PriorityScore*100, it.Kind, it.Headline, it.Action)
	}
}

func cmdExplain(args []string) {
	fs := flag.NewFlagSet("explain", flag.ExitOnError)
	dbPath := fs.String("db", "", "Path to SQLite database")
	repoPath := fs.String("repo", ".", "Repo root")
	path := fs.String("path", "", "File path (partial match)")
	qualified := fs.String("qualified", "", "Qualified symbol name (partial match)")
	fs.Parse(args)

	if *dbPath == "" {
		fmt.Fprintln(os.Stderr, "error: --db is required")
		os.Exit(1)
	}
	if *path == "" && *qualified == "" {
		fmt.Fprintln(os.Stderr, "error: --path or --qualified required")
		os.Exit(1)
	}

	s := openStore(*dbPath)
	defer s.Close()

	zones, _, err := signals.Collect(s, *repoPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	found := false
	for _, z := range zones {
		if *path != "" && !strings.Contains(z.Path, *path) {
			continue
		}
		if *qualified != "" && !strings.Contains(z.Qualified, *qualified) {
			continue
		}
		found = true
		score := correlate.Score(z)
		fmt.Printf("Zone: %s", z.Path)
		if z.Qualified != "" {
			fmt.Printf(" (%s)", z.Qualified)
		}
		fmt.Printf("\nPriority score: %.0f/100\nSignals contributing: %d\n", score*100, z.SignalCount)
		if z.BlastScore >= 0 {
			fmt.Printf("  blast:    %.0f/100 (fan-in %d)\n", z.BlastScore*100, z.BlastFanIn)
		}
		if z.SentinelGap >= 0 {
			fmt.Printf("  sentinel: gap %.0f%% (0=well covered, 100=no coverage)\n", z.SentinelGap*100)
		}
		if z.HunterScore >= 0 {
			fmt.Printf("  hunter:   %.0f%% fix ratio (%d bug-fix commits)\n", z.HunterScore*100, z.HunterFixes)
		}
		if z.ChurnScore >= 0 {
			fmt.Printf("  churn:    %.0f%% relative churn\n", z.ChurnScore*100)
		}
		if z.DepVulnScore >= 0 {
			fmt.Printf("  dep:      CVE score %.0f/100", z.DepVulnScore*100)
			if len(z.DepVulnIDs) > 0 {
				fmt.Printf(" (%s)", strings.Join(z.DepVulnIDs, ", "))
			}
			fmt.Println()
		}
		fmt.Println()
	}

	if !found {
		fmt.Println("No matching zone found.")
	}
}

func cmdPurge(args []string) {
	fs := flag.NewFlagSet("purge", flag.ExitOnError)
	dbPath := fs.String("db", "", "Path to SQLite database")
	olderThan := fs.Int("older-than", 30, "Delete assessments older than N days")
	fs.Parse(args)

	if *dbPath == "" {
		fmt.Fprintln(os.Stderr, "error: --db is required")
		os.Exit(1)
	}

	s := openStore(*dbPath)
	defer s.Close()

	cutoff := time.Now().AddDate(0, 0, -*olderThan).Unix()
	n, err := s.PurgeOldAssessments(cutoff)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Purged %d assessments older than %d days.\n", n, *olderThan)
}

func agentNames(present map[string]bool) []string {
	var out []string
	for name, ok := range present {
		if ok {
			out = append(out, name)
		}
	}
	return out
}

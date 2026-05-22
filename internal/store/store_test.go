package store

import (
	"os"
	"testing"
	"time"
)

// openTestStore creates a temp DB, sets up all necessary schemas, and returns
// the store plus a cleanup function.
func openTestStore(t *testing.T) (*Store, func()) {
	t.Helper()
	f, err := os.CreateTemp("", "council_test_*.db")
	if err != nil {
		t.Fatalf("temp file: %v", err)
	}
	f.Close()

	s, err := Open(f.Name())
	if err != nil {
		os.Remove(f.Name())
		t.Fatalf("open store: %v", err)
	}

	// Create archaeologist + agent tables needed by our queries.
	if _, err := s.db.Exec(archaeoSchema + agentSchemas); err != nil {
		s.Close()
		os.Remove(f.Name())
		t.Fatalf("setup schemas: %v", err)
	}

	return s, func() {
		s.Close()
		os.Remove(f.Name())
	}
}

// Minimal archaeologist schema (files + symbols + file_commits + commits).
const archaeoSchema = `
CREATE TABLE IF NOT EXISTS files (
    id      INTEGER PRIMARY KEY,
    path    TEXT NOT NULL UNIQUE,
    package TEXT NOT NULL DEFAULT '',
    loc     INTEGER NOT NULL DEFAULT 0,
    is_test INTEGER NOT NULL DEFAULT 0,
    is_generated INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS symbols (
    id        INTEGER PRIMARY KEY,
    kind      TEXT NOT NULL DEFAULT 'func',
    name      TEXT NOT NULL DEFAULT '',
    qualified TEXT NOT NULL UNIQUE,
    file_id   INTEGER REFERENCES files(id),
    line_start INTEGER NOT NULL DEFAULT 0,
    line_end   INTEGER NOT NULL DEFAULT 0,
    signature  TEXT NOT NULL DEFAULT '',
    doc        TEXT NOT NULL DEFAULT '',
    exported   INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS commits (
    hash    TEXT PRIMARY KEY,
    author  TEXT NOT NULL DEFAULT '',
    email   TEXT NOT NULL DEFAULT '',
    ts      INTEGER NOT NULL DEFAULT 0,
    subject TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS file_commits (
    file_id     INTEGER NOT NULL REFERENCES files(id),
    commit_hash TEXT NOT NULL REFERENCES commits(hash),
    added       INTEGER NOT NULL DEFAULT 0,
    deleted     INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (file_id, commit_hash)
);
`

// Minimal agent schemas matching the real agents.
const agentSchemas = `
CREATE TABLE IF NOT EXISTS blast_metrics (
    symbol_id     INTEGER PRIMARY KEY,
    fan_in        INTEGER NOT NULL DEFAULT 0,
    fan_out       INTEGER NOT NULL DEFAULT 0,
    transitive_in INTEGER NOT NULL DEFAULT 0,
    is_exported   INTEGER NOT NULL DEFAULT 0,
    is_interface  INTEGER NOT NULL DEFAULT 0,
    risk_score    REAL NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS sentinel_coverage (
    symbol_id      INTEGER PRIMARY KEY,
    is_tested      INTEGER NOT NULL DEFAULT 0,
    direct_tests   INTEGER NOT NULL DEFAULT 0,
    indirect_tests INTEGER NOT NULL DEFAULT 0,
    min_depth      INTEGER NOT NULL DEFAULT 0,
    has_error_test INTEGER NOT NULL DEFAULT 0,
    quality_score  REAL NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS hunter_file_stats (
    file_id        INTEGER PRIMARY KEY,
    total_commits  INTEGER NOT NULL DEFAULT 0,
    fix_commits    INTEGER NOT NULL DEFAULT 0,
    fix_ratio      REAL NOT NULL DEFAULT 0,
    unique_authors INTEGER NOT NULL DEFAULT 0,
    last_fix_ts    INTEGER NOT NULL DEFAULT 0,
    bus_factor     INTEGER NOT NULL DEFAULT 1,
    risk_score     REAL NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS dep_modules (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    path           TEXT NOT NULL UNIQUE,
    version        TEXT NOT NULL DEFAULT '',
    latest_version TEXT,
    license        TEXT,
    license_ok     INTEGER NOT NULL DEFAULT 1,
    last_commit_ts INTEGER,
    is_abandoned   INTEGER NOT NULL DEFAULT 0,
    direct         INTEGER NOT NULL DEFAULT 1,
    ecosystem      TEXT NOT NULL DEFAULT 'go'
);
CREATE TABLE IF NOT EXISTS dep_vulnerabilities (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    module_id INTEGER NOT NULL REFERENCES dep_modules(id),
    vuln_id   TEXT NOT NULL,
    severity  TEXT NOT NULL DEFAULT '',
    cvss_score REAL,
    summary   TEXT NOT NULL DEFAULT '',
    fixed_in  TEXT,
    blast_risk REAL NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS hunter_cochange (
    file_a     INTEGER NOT NULL REFERENCES files(id),
    file_b     INTEGER NOT NULL REFERENCES files(id),
    co_commits INTEGER NOT NULL DEFAULT 0,
    has_edge   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (file_a, file_b)
);
`

// ---- helpers ----

func insertFile(t *testing.T, s *Store, id int, path string) {
	t.Helper()
	_, err := s.db.Exec(`INSERT INTO files(id,path,package) VALUES(?,?,?)`, id, path, "main")
	if err != nil {
		t.Fatalf("insert file: %v", err)
	}
}

func insertSymbol(t *testing.T, s *Store, id, fileID int, qualified string) {
	t.Helper()
	_, err := s.db.Exec(
		`INSERT INTO symbols(id,qualified,file_id,kind,name) VALUES(?,?,?,'func',?)`,
		id, qualified, fileID, qualified)
	if err != nil {
		t.Fatalf("insert symbol: %v", err)
	}
}

// ---- tests ----

func TestMigrate_CreatesCouncilTables(t *testing.T) {
	s, cleanup := openTestStore(t)
	defer cleanup()

	for _, table := range []string{"council_assessments", "council_action_items", "council_meta"} {
		if !s.tableExists(table) {
			t.Errorf("table %s not created", table)
		}
	}
}

func TestAgentsPresent_AllAbsent(t *testing.T) {
	s, cleanup := openTestStore(t)
	defer cleanup()

	// Tables exist but are empty.
	present := s.AgentsPresent()
	for name, ok := range present {
		if ok {
			t.Errorf("agent %s should not be present (empty table)", name)
		}
	}
}

func TestAgentsPresent_BlastPresent(t *testing.T) {
	s, cleanup := openTestStore(t)
	defer cleanup()

	insertFile(t, s, 1, "internal/pay.go")
	insertSymbol(t, s, 1, 1, "pay.Charge")
	s.db.Exec(`INSERT INTO blast_metrics(symbol_id,risk_score) VALUES(1, 80.0)`)

	present := s.AgentsPresent()
	if !present["blast"] {
		t.Error("blast should be present")
	}
	if present["sentinel"] {
		t.Error("sentinel should not be present")
	}
}

func TestBlastMetrics(t *testing.T) {
	s, cleanup := openTestStore(t)
	defer cleanup()

	insertFile(t, s, 1, "internal/pay.go")
	insertSymbol(t, s, 1, 1, "pay.Charge")
	s.db.Exec(`INSERT INTO blast_metrics(symbol_id,risk_score,fan_in,transitive_in) VALUES(1,75.0,10,40)`)

	metrics, err := s.BlastMetrics()
	if err != nil {
		t.Fatal(err)
	}
	if len(metrics) != 1 {
		t.Fatalf("expected 1 metric, got %d", len(metrics))
	}
	m := metrics[0]
	if m.Qualified != "pay.Charge" {
		t.Errorf("qualified = %q", m.Qualified)
	}
	if m.Path != "internal/pay.go" {
		t.Errorf("path = %q", m.Path)
	}
	if m.RiskScore != 75.0 {
		t.Errorf("risk_score = %f", m.RiskScore)
	}
	if m.FanIn != 10 {
		t.Errorf("fan_in = %d", m.FanIn)
	}
}

func TestSentinelCoverage(t *testing.T) {
	s, cleanup := openTestStore(t)
	defer cleanup()

	insertFile(t, s, 1, "internal/auth.go")
	insertSymbol(t, s, 1, 1, "auth.Login")
	s.db.Exec(`INSERT INTO sentinel_coverage(symbol_id,direct_tests) VALUES(1,0)`)

	covs, err := s.SentinelCoverage()
	if err != nil {
		t.Fatal(err)
	}
	if len(covs) != 1 {
		t.Fatalf("expected 1, got %d", len(covs))
	}
	if covs[0].DirectTests != 0 {
		t.Errorf("expected 0 tests, got %d", covs[0].DirectTests)
	}
	if covs[0].Qualified != "auth.Login" {
		t.Errorf("qualified = %q", covs[0].Qualified)
	}
}

func TestHunterFileStats(t *testing.T) {
	s, cleanup := openTestStore(t)
	defer cleanup()

	insertFile(t, s, 1, "cmd/main.go")
	s.db.Exec(`INSERT INTO hunter_file_stats(file_id,total_commits,fix_commits,fix_ratio) VALUES(1,20,8,0.4)`)

	stats, err := s.HunterFileStats()
	if err != nil {
		t.Fatal(err)
	}
	if len(stats) != 1 {
		t.Fatalf("expected 1, got %d", len(stats))
	}
	if stats[0].FixCommits != 8 {
		t.Errorf("fix_commits = %d", stats[0].FixCommits)
	}
	if stats[0].FixRatio != 0.4 {
		t.Errorf("fix_ratio = %f", stats[0].FixRatio)
	}
	if stats[0].Path != "cmd/main.go" {
		t.Errorf("path = %q", stats[0].Path)
	}
}

func TestDepVulnerabilities(t *testing.T) {
	s, cleanup := openTestStore(t)
	defer cleanup()

	s.db.Exec(`INSERT INTO dep_modules(id,path,version) VALUES(1,'golang.org/x/crypto','v0.0.1')`)
	s.db.Exec(`INSERT INTO dep_vulnerabilities(module_id,vuln_id,severity,cvss_score,summary,fixed_in)
               VALUES(1,'GO-2024-9999','CRITICAL',9.1,'desc','v0.31.0')`)

	vulns, err := s.DepVulnerabilities()
	if err != nil {
		t.Fatal(err)
	}
	if len(vulns) != 1 {
		t.Fatalf("expected 1, got %d", len(vulns))
	}
	v := vulns[0]
	if v.Module != "golang.org/x/crypto" {
		t.Errorf("module = %q", v.Module)
	}
	if v.ID != "GO-2024-9999" {
		t.Errorf("vuln_id = %q", v.ID)
	}
	if v.CVSS != 9.1 {
		t.Errorf("cvss = %f", v.CVSS)
	}
	if !v.HasFix {
		t.Error("has_fix should be true when fixed_in is set")
	}
}

func TestBlastMetrics_ExcludesTestFiles(t *testing.T) {
	s, cleanup := openTestStore(t)
	defer cleanup()

	// is_test=0 → should appear; is_test=1 → must be excluded
	s.db.Exec(`INSERT INTO files(id,path,package,is_test) VALUES(1,'pkg/foo.go','foo',0)`)
	s.db.Exec(`INSERT INTO files(id,path,package,is_test) VALUES(2,'pkg/foo_test.go','foo',1)`)
	s.db.Exec(`INSERT INTO symbols(id,qualified,file_id,kind,name) VALUES(1,'foo.F',1,'func','F')`)
	s.db.Exec(`INSERT INTO symbols(id,qualified,file_id,kind,name) VALUES(2,'foo.TestF',2,'func','TestF')`)
	s.db.Exec(`INSERT INTO blast_metrics(symbol_id,risk_score) VALUES(1,60.0)`)
	s.db.Exec(`INSERT INTO blast_metrics(symbol_id,risk_score) VALUES(2,80.0)`)

	metrics, err := s.BlastMetrics()
	if err != nil {
		t.Fatal(err)
	}
	if len(metrics) != 1 {
		t.Fatalf("expected 1 metric (test file excluded), got %d", len(metrics))
	}
	if metrics[0].Qualified != "foo.F" {
		t.Errorf("wrong symbol returned: %q", metrics[0].Qualified)
	}
}

func TestSentinelCoverage_ExcludesTestFiles(t *testing.T) {
	s, cleanup := openTestStore(t)
	defer cleanup()

	s.db.Exec(`INSERT INTO files(id,path,package,is_test) VALUES(1,'pkg/auth.go','auth',0)`)
	s.db.Exec(`INSERT INTO files(id,path,package,is_test) VALUES(2,'pkg/auth_test.go','auth',1)`)
	s.db.Exec(`INSERT INTO symbols(id,qualified,file_id,kind,name) VALUES(1,'auth.Login',1,'func','Login')`)
	s.db.Exec(`INSERT INTO symbols(id,qualified,file_id,kind,name) VALUES(2,'auth.TestLogin',2,'func','TestLogin')`)
	s.db.Exec(`INSERT INTO sentinel_coverage(symbol_id,direct_tests,quality_score,is_tested) VALUES(1,0,0.0,0)`)
	s.db.Exec(`INSERT INTO sentinel_coverage(symbol_id,direct_tests,quality_score,is_tested) VALUES(2,0,0.0,0)`)

	covs, err := s.SentinelCoverage()
	if err != nil {
		t.Fatal(err)
	}
	if len(covs) != 1 {
		t.Fatalf("expected 1 coverage row (test file excluded), got %d", len(covs))
	}
	if covs[0].Qualified != "auth.Login" {
		t.Errorf("wrong symbol: %q", covs[0].Qualified)
	}
}

func TestDepVulnerabilities_NoFix(t *testing.T) {
	s, cleanup := openTestStore(t)
	defer cleanup()

	s.db.Exec(`INSERT INTO dep_modules(id,path,version) VALUES(1,'evil/dep','v1.0.0')`)
	s.db.Exec(`INSERT INTO dep_vulnerabilities(module_id,vuln_id,severity,cvss_score,summary)
               VALUES(1,'GO-2025-0001','HIGH',7.5,'no fix yet')`)

	vulns, _ := s.DepVulnerabilities()
	if len(vulns) != 1 || vulns[0].HasFix {
		t.Error("has_fix should be false when fixed_in is NULL")
	}
}

func TestDepModuleProblems(t *testing.T) {
	s, cleanup := openTestStore(t)
	defer cleanup()

	s.db.Exec(`INSERT INTO dep_modules(path,version,is_abandoned,license_ok,license)
               VALUES('old/pkg','v0.1',1,0,'AGPL-3.0')`)
	s.db.Exec(`INSERT INTO dep_modules(path,version,license_ok) VALUES('good/pkg','v1.0',1)`)

	mods, err := s.DepModuleProblems()
	if err != nil {
		t.Fatal(err)
	}
	if len(mods) != 1 {
		t.Fatalf("expected 1 problem module, got %d", len(mods))
	}
	if !mods[0].IsAbandoned {
		t.Error("should be abandoned")
	}
	if mods[0].LicenseOK {
		t.Error("license should not be ok")
	}
}

func TestFileChurn(t *testing.T) {
	s, cleanup := openTestStore(t)
	defer cleanup()

	insertFile(t, s, 1, "hot/file.go")
	for i, h := range []string{"a1", "a2", "a3"} {
		s.db.Exec(`INSERT INTO commits(hash,author,email,ts,subject) VALUES(?,?,?,?,?)`,
			h, "A", "a@b", i, "fix")
		s.db.Exec(`INSERT INTO file_commits(file_id,commit_hash,added,deleted) VALUES(1,?,?,?)`,
			h, 5, 2)
	}

	churns, err := s.FileChurn()
	if err != nil {
		t.Fatal(err)
	}
	if len(churns) != 1 {
		t.Fatalf("expected 1, got %d", len(churns))
	}
	if churns[0].CommitCount != 3 {
		t.Errorf("commit_count = %d", churns[0].CommitCount)
	}
	if churns[0].LinesAdded != 15 {
		t.Errorf("lines_added = %d", churns[0].LinesAdded)
	}
}

func TestCoChangePairs(t *testing.T) {
	s, cleanup := openTestStore(t)
	defer cleanup()

	insertFile(t, s, 1, "pkg/a.go")
	insertFile(t, s, 2, "pkg/b.go")
	insertFile(t, s, 3, "pkg/c.go")

	// a↔b: 10 co-commits without edge (implicit coupling)
	s.db.Exec(`INSERT INTO hunter_cochange(file_a,file_b,co_commits,has_edge) VALUES(1,2,10,0)`)
	// b↔c: 3 co-commits without edge
	s.db.Exec(`INSERT INTO hunter_cochange(file_a,file_b,co_commits,has_edge) VALUES(2,3,3,0)`)
	// a↔c: 15 co-commits but has explicit edge — should be excluded
	s.db.Exec(`INSERT INTO hunter_cochange(file_a,file_b,co_commits,has_edge) VALUES(1,3,15,1)`)

	pairs, err := s.CoChangePairs(3)
	if err != nil {
		t.Fatal(err)
	}
	if len(pairs) != 2 {
		t.Fatalf("expected 2 pairs (has_edge=1 excluded), got %d", len(pairs))
	}
	// Ordered DESC by co_commits: a↔b (10) first
	if pairs[0].PathA != "pkg/a.go" || pairs[0].PathB != "pkg/b.go" {
		t.Errorf("unexpected pair[0]: %+v", pairs[0])
	}
	if pairs[0].CoCommits != 10 {
		t.Errorf("co_commits = %d, want 10", pairs[0].CoCommits)
	}
}

func TestCoChangePairs_MinThreshold(t *testing.T) {
	s, cleanup := openTestStore(t)
	defer cleanup()

	insertFile(t, s, 1, "pkg/a.go")
	insertFile(t, s, 2, "pkg/b.go")
	// Only 2 co-commits — below minCoCommits=3 threshold
	s.db.Exec(`INSERT INTO hunter_cochange(file_a,file_b,co_commits,has_edge) VALUES(1,2,2,0)`)

	pairs, err := s.CoChangePairs(3)
	if err != nil {
		t.Fatal(err)
	}
	if len(pairs) != 0 {
		t.Errorf("expected 0 pairs below threshold, got %d", len(pairs))
	}
}

func TestSaveAndLoadAssessment(t *testing.T) {
	s, cleanup := openTestStore(t)
	defer cleanup()

	a := &Assessment{
		RepoPath:      "/repo",
		AgentsPresent: []string{"blast", "sentinel"},
		Summary:       map[string]any{"zones": 42},
		HealthScore:   73.5,
	}
	id, err := s.SaveAssessment(a)
	if err != nil {
		t.Fatal(err)
	}
	if id <= 0 {
		t.Error("expected positive ID")
	}

	items := []ActionItem{
		{AssessmentID: id, Rank: 1, Kind: "fix_untested_critical",
			PriorityScore: 0.9, Signals: []string{"blast", "sentinel"},
			Path: "internal/pay.go", Headline: "pay.Charge — 0 tests", Action: "write tests"},
	}
	if err := s.SaveActionItems(items); err != nil {
		t.Fatal(err)
	}

	loaded, err := s.LoadActionItems(id, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 1 {
		t.Fatalf("expected 1 item, got %d", len(loaded))
	}
	it := loaded[0]
	if it.Kind != "fix_untested_critical" {
		t.Errorf("kind = %q", it.Kind)
	}
	if len(it.Signals) != 2 {
		t.Errorf("signals = %v", it.Signals)
	}
}

func TestLatestAssessmentID(t *testing.T) {
	s, cleanup := openTestStore(t)
	defer cleanup()

	_, err := s.LatestAssessmentID("/repo")
	if err == nil {
		t.Error("expected error when no assessments exist")
	}

	s.SaveAssessment(&Assessment{RepoPath: "/repo", AgentsPresent: []string{}, Summary: map[string]any{}, HealthScore: 80})
	id2, _ := s.SaveAssessment(&Assessment{RepoPath: "/repo", AgentsPresent: []string{}, Summary: map[string]any{}, HealthScore: 60})

	got, err := s.LatestAssessmentID("/repo")
	if err != nil {
		t.Fatal(err)
	}
	if got != id2 {
		t.Errorf("expected latest id %d, got %d", id2, got)
	}
}

func TestPurgeOldAssessments(t *testing.T) {
	s, cleanup := openTestStore(t)
	defer cleanup()

	old := &Assessment{RepoPath: "/r", AgentsPresent: []string{}, Summary: map[string]any{}, HealthScore: 50}
	id, _ := s.SaveAssessment(old)
	// Back-date it.
	s.db.Exec(`UPDATE council_assessments SET created_at=? WHERE id=?`,
		time.Now().AddDate(0, 0, -60).Unix(), id)

	s.SaveAssessment(&Assessment{RepoPath: "/r", AgentsPresent: []string{}, Summary: map[string]any{}, HealthScore: 90})

	deleted, err := s.PurgeOldAssessments(time.Now().AddDate(0, 0, -30).Unix())
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 1 {
		t.Errorf("expected 1 deleted, got %d", deleted)
	}
}

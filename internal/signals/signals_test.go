package signals

import (
	"os"
	"testing"

	"github.com/yoannchl/the-council/internal/store"
)

// openDB creates a temp SQLite DB with all required schemas.
func openDB(t *testing.T) (*store.Store, func()) {
	t.Helper()
	f, err := os.CreateTemp("", "signals_test_*.db")
	if err != nil {
		t.Fatalf("temp file: %v", err)
	}
	f.Close()

	s, err := store.Open(f.Name())
	if err != nil {
		os.Remove(f.Name())
		t.Fatalf("open store: %v", err)
	}

	// Same schemas as in store_test.go — kept in sync with real agents.
	if _, err := s.DB().Exec(testSchema); err != nil {
		s.Close()
		os.Remove(f.Name())
		t.Fatalf("setup schema: %v", err)
	}

	return s, func() { s.Close(); os.Remove(f.Name()) }
}

const testSchema = `
CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY, path TEXT NOT NULL UNIQUE,
    package TEXT NOT NULL DEFAULT '', loc INTEGER NOT NULL DEFAULT 0,
    is_test INTEGER NOT NULL DEFAULT 0, is_generated INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS symbols (
    id INTEGER PRIMARY KEY, kind TEXT NOT NULL DEFAULT 'func',
    name TEXT NOT NULL DEFAULT '', qualified TEXT NOT NULL UNIQUE,
    file_id INTEGER REFERENCES files(id),
    line_start INTEGER NOT NULL DEFAULT 0, line_end INTEGER NOT NULL DEFAULT 0,
    signature TEXT NOT NULL DEFAULT '', doc TEXT NOT NULL DEFAULT '',
    exported INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS commits (
    hash TEXT PRIMARY KEY, author TEXT NOT NULL DEFAULT '',
    email TEXT NOT NULL DEFAULT '', ts INTEGER NOT NULL DEFAULT 0,
    subject TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS file_commits (
    file_id INTEGER NOT NULL REFERENCES files(id),
    commit_hash TEXT NOT NULL REFERENCES commits(hash),
    added INTEGER NOT NULL DEFAULT 0, deleted INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (file_id, commit_hash)
);
CREATE TABLE IF NOT EXISTS blast_metrics (
    symbol_id INTEGER PRIMARY KEY, fan_in INTEGER NOT NULL DEFAULT 0,
    fan_out INTEGER NOT NULL DEFAULT 0, transitive_in INTEGER NOT NULL DEFAULT 0,
    is_exported INTEGER NOT NULL DEFAULT 0, is_interface INTEGER NOT NULL DEFAULT 0,
    risk_score REAL NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS sentinel_coverage (
    symbol_id INTEGER PRIMARY KEY, is_tested INTEGER NOT NULL DEFAULT 0,
    direct_tests INTEGER NOT NULL DEFAULT 0, indirect_tests INTEGER NOT NULL DEFAULT 0,
    min_depth INTEGER NOT NULL DEFAULT 0, has_error_test INTEGER NOT NULL DEFAULT 0,
    quality_score REAL NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS hunter_file_stats (
    file_id INTEGER PRIMARY KEY, total_commits INTEGER NOT NULL DEFAULT 0,
    fix_commits INTEGER NOT NULL DEFAULT 0, fix_ratio REAL NOT NULL DEFAULT 0,
    unique_authors INTEGER NOT NULL DEFAULT 0, last_fix_ts INTEGER NOT NULL DEFAULT 0,
    bus_factor INTEGER NOT NULL DEFAULT 1, risk_score REAL NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS dep_modules (
    id INTEGER PRIMARY KEY AUTOINCREMENT, path TEXT NOT NULL UNIQUE,
    version TEXT NOT NULL DEFAULT '', latest_version TEXT, license TEXT,
    license_ok INTEGER NOT NULL DEFAULT 1, last_commit_ts INTEGER,
    is_abandoned INTEGER NOT NULL DEFAULT 0, direct INTEGER NOT NULL DEFAULT 1,
    ecosystem TEXT NOT NULL DEFAULT 'go'
);
CREATE TABLE IF NOT EXISTS dep_vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    module_id INTEGER NOT NULL REFERENCES dep_modules(id),
    vuln_id TEXT NOT NULL, severity TEXT NOT NULL DEFAULT '',
    cvss_score REAL, summary TEXT NOT NULL DEFAULT '', fixed_in TEXT,
    blast_risk REAL NOT NULL DEFAULT 0
);
`

func TestCollect_AllAgentsAbsent(t *testing.T) {
	s, cleanup := openDB(t)
	defer cleanup()

	zones, missing, err := Collect(s, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(zones) != 0 {
		t.Errorf("expected no zones, got %d", len(zones))
	}
	// All 5 agents missing
	if len(missing) != 5 {
		t.Errorf("expected 5 missing agents, got %d: %v", len(missing), missing)
	}
}

func TestCollect_BlastSignal(t *testing.T) {
	s, cleanup := openDB(t)
	defer cleanup()

	s.DB().Exec(`INSERT INTO files(id,path,package) VALUES(1,'internal/pay.go','pay')`)
	s.DB().Exec(`INSERT INTO symbols(id,qualified,file_id,kind,name) VALUES(1,'pay.Charge',1,'func','Charge')`)
	s.DB().Exec(`INSERT INTO blast_metrics(symbol_id,risk_score,fan_in) VALUES(1,80.0,15)`)

	zones, missing, err := Collect(s, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(zones) != 1 {
		t.Fatalf("expected 1 zone, got %d", len(zones))
	}

	var z *Zone
	for _, v := range zones {
		z = v
	}

	if z.BlastScore < 0 {
		t.Error("blast score should be set")
	}
	if abs(z.BlastScore-0.8) > 1e-9 {
		t.Errorf("blast score = %f, want 0.8", z.BlastScore)
	}

	// blast present, others absent
	for _, m := range missing {
		if m == "blast" {
			t.Error("blast should not be in missing")
		}
	}
}

func TestCollect_SentinelGap_NoTests(t *testing.T) {
	s, cleanup := openDB(t)
	defer cleanup()

	s.DB().Exec(`INSERT INTO files(id,path,package) VALUES(1,'pkg/a.go','a')`)
	s.DB().Exec(`INSERT INTO symbols(id,qualified,file_id,kind,name) VALUES(1,'a.Func',1,'func','Func')`)
	s.DB().Exec(`INSERT INTO sentinel_coverage(symbol_id,direct_tests) VALUES(1,0)`)

	zones, _, _ := Collect(s, "")
	for _, z := range zones {
		if z.SentinelGap != 1.0 {
			t.Errorf("expected sentinel gap 1.0, got %f", z.SentinelGap)
		}
	}
}

func TestCollect_SentinelGap_WellTested(t *testing.T) {
	s, cleanup := openDB(t)
	defer cleanup()

	s.DB().Exec(`INSERT INTO files(id,path,package) VALUES(1,'pkg/b.go','b')`)
	s.DB().Exec(`INSERT INTO symbols(id,qualified,file_id,kind,name) VALUES(1,'b.F',1,'func','F')`)
	s.DB().Exec(`INSERT INTO sentinel_coverage(symbol_id,direct_tests) VALUES(1,10)`)

	zones, _, _ := Collect(s, "")
	for _, z := range zones {
		if z.SentinelGap != 0.0 {
			t.Errorf("expected gap 0.0, got %f", z.SentinelGap)
		}
	}
}

func TestCollect_HunterSignal(t *testing.T) {
	s, cleanup := openDB(t)
	defer cleanup()

	s.DB().Exec(`INSERT INTO files(id,path,package) VALUES(1,'cmd/main.go','main')`)
	s.DB().Exec(`INSERT INTO hunter_file_stats(file_id,fix_commits,fix_ratio) VALUES(1,12,0.6)`)

	zones, _, _ := Collect(s, "")
	for _, z := range zones {
		if abs(z.HunterScore-0.6) > 1e-9 {
			t.Errorf("hunter score = %f", z.HunterScore)
		}
		if z.HunterFixes != 12 {
			t.Errorf("hunter fixes = %d", z.HunterFixes)
		}
	}
}

func TestCollect_DepVulnSignal(t *testing.T) {
	s, cleanup := openDB(t)
	defer cleanup()

	s.DB().Exec(`INSERT INTO dep_modules(id,path,version) VALUES(1,'golang.org/x/crypto','v0.0.1')`)
	s.DB().Exec(`INSERT INTO dep_vulnerabilities(module_id,vuln_id,severity,cvss_score,summary)
                 VALUES(1,'GO-2024-9999','CRITICAL',9.1,'bad')`)

	zones, _, _ := Collect(s, "")
	if len(zones) != 1 {
		t.Fatalf("expected 1 zone, got %d", len(zones))
	}
	for _, z := range zones {
		if z.DepVulnScore < 0 {
			t.Error("dep vuln score should be set")
		}
		if abs(z.DepVulnScore-0.91) > 1e-9 {
			t.Errorf("dep vuln score = %f, want 0.91", z.DepVulnScore)
		}
		if len(z.DepVulnIDs) != 1 || z.DepVulnIDs[0] != "GO-2024-9999" {
			t.Errorf("vuln ids = %v", z.DepVulnIDs)
		}
	}
}

func TestCollect_ChurnSignal(t *testing.T) {
	s, cleanup := openDB(t)
	defer cleanup()

	s.DB().Exec(`INSERT INTO files(id,path,package) VALUES(1,'hot.go','main')`)
	s.DB().Exec(`INSERT INTO commits(hash,author,email,ts,subject) VALUES('a','x','x@y',0,'f')`)
	s.DB().Exec(`INSERT INTO file_commits(file_id,commit_hash,added,deleted) VALUES(1,'a',5,2)`)

	zones, _, _ := Collect(s, "")
	for _, z := range zones {
		// 1 commit out of max 1 → churn 1.0
		if z.ChurnScore != 1.0 {
			t.Errorf("churn score = %f, want 1.0", z.ChurnScore)
		}
	}
}

func TestCollect_SignalCount(t *testing.T) {
	s, cleanup := openDB(t)
	defer cleanup()

	s.DB().Exec(`INSERT INTO files(id,path,package) VALUES(1,'x.go','x')`)
	s.DB().Exec(`INSERT INTO symbols(id,qualified,file_id,kind,name) VALUES(1,'x.F',1,'func','F')`)
	s.DB().Exec(`INSERT INTO blast_metrics(symbol_id,risk_score) VALUES(1,50.0)`)
	s.DB().Exec(`INSERT INTO sentinel_coverage(symbol_id,direct_tests) VALUES(1,0)`)

	zones, _, _ := Collect(s, "")
	// May have 1 or 2 zones (symbol-level and/or file-level merged)
	for _, z := range zones {
		if z.BlastScore >= 0 && z.SentinelGap >= 0 && z.SignalCount < 2 {
			t.Errorf("signal count should be ≥2 when both blast and sentinel are present, got %d", z.SignalCount)
		}
	}
}

func TestNormPath_RelativePath(t *testing.T) {
	got := normPath("/repo", "/repo/internal/foo.go")
	if got != "internal/foo.go" {
		t.Errorf("normPath = %q", got)
	}
}

func TestNormPath_AlreadyRelative(t *testing.T) {
	got := normPath("/repo", "internal/foo.go")
	if got != "internal/foo.go" {
		t.Errorf("normPath = %q", got)
	}
}

func TestNormPath_EmptyRoot(t *testing.T) {
	got := normPath("", "/abs/path.go")
	if got != "/abs/path.go" {
		t.Errorf("normPath = %q", got)
	}
}

func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}

package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// Store opens the shared SQLite DB and provides read access to all agent tables
// plus write access to council_* tables.
type Store struct {
	db *sql.DB
}

func Open(dbPath string) (*Store, error) {
	db, err := sql.Open("sqlite3", dbPath+"?_foreign_keys=on")
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("ping db: %w", err)
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

// DB exposes the underlying sql.DB for test setup only.
func (s *Store) DB() *sql.DB { return s.db }

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS council_assessments (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at      INTEGER NOT NULL,
    repo_path       TEXT    NOT NULL,
    agents_present  TEXT    NOT NULL,
    summary         TEXT    NOT NULL,
    health_score    REAL    NOT NULL
);

CREATE TABLE IF NOT EXISTS council_action_items (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id   INTEGER NOT NULL REFERENCES council_assessments(id),
    rank            INTEGER NOT NULL,
    kind            TEXT    NOT NULL,
    priority_score  REAL    NOT NULL,
    signals         TEXT    NOT NULL,
    qualified       TEXT,
    path            TEXT,
    headline        TEXT    NOT NULL,
    action          TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_council_items_rank ON council_action_items(assessment_id, rank);

CREATE TABLE IF NOT EXISTS council_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
`)
	return err
}

// tableExists checks if a table is present in the DB.
func (s *Store) tableExists(name string) bool {
	var n int
	s.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, name).Scan(&n)
	return n > 0
}

// AgentsPresent checks which agent tables exist and have data.
func (s *Store) AgentsPresent() map[string]bool {
	checks := map[string]string{
		"archaeo":  "SELECT 1 FROM files LIMIT 1",
		"blast":    "SELECT 1 FROM blast_metrics LIMIT 1",
		"sentinel": "SELECT 1 FROM sentinel_coverage LIMIT 1",
		"hunter":   "SELECT 1 FROM hunter_file_stats LIMIT 1",
		"dep":      "SELECT 1 FROM dep_vulnerabilities LIMIT 1",
	}
	present := make(map[string]bool, len(checks))
	for name, q := range checks {
		var x int
		err := s.db.QueryRow(q).Scan(&x)
		present[name] = (err == nil)
	}
	return present
}

// ---- blast_metrics ----
// blast_metrics is keyed by symbol_id; join symbols + files to get path/qualified.

type BlastMetric struct {
	Qualified    string
	Path         string
	RiskScore    float64
	FanIn        int
	TransitiveIn int
}

func (s *Store) BlastMetrics() ([]BlastMetric, error) {
	rows, err := s.db.Query(`
SELECT s.qualified, f.path, bm.risk_score, bm.fan_in, bm.transitive_in
FROM blast_metrics bm
JOIN symbols s ON s.id = bm.symbol_id
JOIN files   f ON f.id = s.file_id
WHERE f.is_test = 0`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []BlastMetric
	for rows.Next() {
		var m BlastMetric
		if err := rows.Scan(&m.Qualified, &m.Path, &m.RiskScore, &m.FanIn, &m.TransitiveIn); err != nil {
			continue
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// ---- sentinel_coverage ----
// sentinel_coverage is keyed by symbol_id.
// quality_score (0..1) is the agent's pre-computed coverage quality — more reliable than raw direct_tests.

type SentinelCoverage struct {
	Path         string
	Qualified    string
	DirectTests  int
	QualityScore float64 // 0 = untested, 1 = well covered
	IsTested     bool
}

func (s *Store) SentinelCoverage() ([]SentinelCoverage, error) {
	rows, err := s.db.Query(`
SELECT f.path, s.qualified, sc.direct_tests, sc.quality_score, sc.is_tested
FROM sentinel_coverage sc
JOIN symbols s ON s.id = sc.symbol_id
JOIN files   f ON f.id = s.file_id
WHERE f.is_test = 0`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SentinelCoverage
	for rows.Next() {
		var c SentinelCoverage
		var isTested int
		if err := rows.Scan(&c.Path, &c.Qualified, &c.DirectTests, &c.QualityScore, &isTested); err != nil {
			continue
		}
		c.IsTested = isTested == 1
		out = append(out, c)
	}
	return out, rows.Err()
}

// SentinelFindingMaxRisk returns the worst sentinel_findings risk_score per path.
// Only includes paths where risk_score > 0.
type SentinelFinding struct {
	Path      string
	MaxRisk   float64 // 0..100 from sentinel
	Severity  string
}

func (s *Store) SentinelFindingMaxRisk() ([]SentinelFinding, error) {
	rows, err := s.db.Query(`
SELECT path, MAX(risk_score), severity
FROM sentinel_findings
WHERE risk_score > 0
GROUP BY path`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SentinelFinding
	for rows.Next() {
		var f SentinelFinding
		if err := rows.Scan(&f.Path, &f.MaxRisk, &f.Severity); err != nil {
			continue
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// ---- hunter_file_stats ----
// hunter_file_stats is keyed by file_id; join files to get path.
// Column is fix_commits (not bug_fixes).

type HunterFileStat struct {
	Path       string
	FixCommits int
	FixRatio   float64
}

func (s *Store) HunterFileStats() ([]HunterFileStat, error) {
	// Require at least 5 total commits to avoid fix_ratio=1.0 artefacts on sparse history.
	rows, err := s.db.Query(`
SELECT f.path, hfs.fix_commits, hfs.fix_ratio
FROM hunter_file_stats hfs
JOIN files f ON f.id = hfs.file_id
WHERE hfs.total_commits >= 5`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HunterFileStat
	for rows.Next() {
		var h HunterFileStat
		if err := rows.Scan(&h.Path, &h.FixCommits, &h.FixRatio); err != nil {
			continue
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// ---- dep_vulnerabilities ----
// dep_vulnerabilities has module_id FK to dep_modules; column is cvss_score.
// fixed_in non-null means a fix is available.

type DepVulnerability struct {
	Module   string // dep_modules.path
	ID       string // vuln_id
	Severity string
	CVSS     float64
	HasFix   bool
}

func (s *Store) DepVulnerabilities() ([]DepVulnerability, error) {
	rows, err := s.db.Query(`
SELECT dm.path, dv.vuln_id, dv.severity, COALESCE(dv.cvss_score, 0.0),
       CASE WHEN dv.fixed_in IS NOT NULL AND dv.fixed_in != '' THEN 1 ELSE 0 END
FROM dep_vulnerabilities dv
JOIN dep_modules dm ON dm.id = dv.module_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DepVulnerability
	for rows.Next() {
		var v DepVulnerability
		var hasFix int
		if err := rows.Scan(&v.Module, &v.ID, &v.Severity, &v.CVSS, &hasFix); err != nil {
			continue
		}
		v.HasFix = hasFix == 1
		out = append(out, v)
	}
	return out, rows.Err()
}

// ---- dep_modules bad license / abandoned ----

type DepModule struct {
	Path        string
	Version     string
	IsAbandoned bool
	LicenseOK   bool
	License     string
}

func (s *Store) DepModuleProblems() ([]DepModule, error) {
	rows, err := s.db.Query(`
SELECT path, version, is_abandoned, license_ok, COALESCE(license,'')
FROM dep_modules
WHERE is_abandoned=1 OR license_ok=0`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DepModule
	for rows.Next() {
		var m DepModule
		var abandoned, licOK int
		if err := rows.Scan(&m.Path, &m.Version, &abandoned, &licOK, &m.License); err != nil {
			continue
		}
		m.IsAbandoned = abandoned == 1
		m.LicenseOK = licOK == 1
		out = append(out, m)
	}
	return out, rows.Err()
}

// ---- archaeo churn (file_commits) ----

type FileChurn struct {
	Path        string
	CommitCount int
	LinesAdded  int
	LinesDeleted int
}

func (s *Store) FileChurn() ([]FileChurn, error) {
	// Only return files with at least 3 commits — single-commit entries are noise.
	rows, err := s.db.Query(`
SELECT f.path,
       COUNT(fc.commit_hash)      AS commit_count,
       COALESCE(SUM(fc.added),0)   AS lines_added,
       COALESCE(SUM(fc.deleted),0) AS lines_deleted
FROM file_commits fc
JOIN files f ON f.id = fc.file_id
GROUP BY fc.file_id
HAVING commit_count >= 3`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FileChurn
	for rows.Next() {
		var c FileChurn
		if err := rows.Scan(&c.Path, &c.CommitCount, &c.LinesAdded, &c.LinesDeleted); err != nil {
			continue
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ---- write council results ----

type Assessment struct {
	ID            int64
	CreatedAt     int64
	RepoPath      string
	AgentsPresent []string
	Summary       map[string]any
	HealthScore   float64
}

func (s *Store) SaveAssessment(a *Assessment) (int64, error) {
	agents, _ := json.Marshal(a.AgentsPresent)
	summary, _ := json.Marshal(a.Summary)
	a.CreatedAt = time.Now().Unix()
	res, err := s.db.Exec(`
INSERT INTO council_assessments(created_at,repo_path,agents_present,summary,health_score)
VALUES(?,?,?,?,?)`,
		a.CreatedAt, a.RepoPath, string(agents), string(summary), a.HealthScore)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

type ActionItem struct {
	AssessmentID  int64
	Rank          int
	Kind          string
	PriorityScore float64
	Signals       []string
	Qualified     string
	Path          string
	Headline      string
	Action        string
}

func (s *Store) SaveActionItems(items []ActionItem) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`
INSERT INTO council_action_items
(assessment_id,rank,kind,priority_score,signals,qualified,path,headline,action)
VALUES(?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		tx.Rollback()
		return err
	}
	defer stmt.Close()
	for _, it := range items {
		sigs, _ := json.Marshal(it.Signals)
		if _, err := stmt.Exec(
			it.AssessmentID, it.Rank, it.Kind, it.PriorityScore,
			string(sigs), it.Qualified, it.Path, it.Headline, it.Action,
		); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// LoadActionItems returns the action items for a given assessment, ordered by rank.
func (s *Store) LoadActionItems(assessmentID int64, limit int) ([]ActionItem, error) {
	rows, err := s.db.Query(`
SELECT rank,kind,priority_score,signals,COALESCE(qualified,''),COALESCE(path,''),headline,action
FROM council_action_items
WHERE assessment_id=?
ORDER BY rank ASC
LIMIT ?`, assessmentID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ActionItem
	for rows.Next() {
		var it ActionItem
		var sigsJSON string
		if err := rows.Scan(&it.Rank, &it.Kind, &it.PriorityScore, &sigsJSON,
			&it.Qualified, &it.Path, &it.Headline, &it.Action); err != nil {
			continue
		}
		json.Unmarshal([]byte(sigsJSON), &it.Signals)
		it.AssessmentID = assessmentID
		out = append(out, it)
	}
	return out, rows.Err()
}

// LatestAssessmentID returns the ID of the most recent assessment for the given repo.
func (s *Store) LatestAssessmentID(repoPath string) (int64, error) {
	var id int64
	err := s.db.QueryRow(`
SELECT id FROM council_assessments WHERE repo_path=? ORDER BY created_at DESC, id DESC LIMIT 1`, repoPath).Scan(&id)
	return id, err
}

// PurgeOldAssessments deletes assessments older than the given Unix timestamp.
func (s *Store) PurgeOldAssessments(olderThan int64) (int64, error) {
	rows, err := s.db.Query(`SELECT id FROM council_assessments WHERE created_at < ?`, olderThan)
	if err != nil {
		return 0, err
	}
	var ids []int64
	for rows.Next() {
		var id int64
		rows.Scan(&id)
		ids = append(ids, id)
	}
	rows.Close()

	var deleted int64
	for _, id := range ids {
		s.db.Exec(`DELETE FROM council_action_items WHERE assessment_id=?`, id)
		res, _ := s.db.Exec(`DELETE FROM council_assessments WHERE id=?`, id)
		n, _ := res.RowsAffected()
		deleted += n
	}
	return deleted, nil
}

// MaxCommitCount returns the max commit_count across all files (for normalisation).
func (s *Store) MaxCommitCount() int {
	var n int
	s.db.QueryRow(`
SELECT COALESCE(MAX(cnt),1) FROM (
    SELECT COUNT(*) AS cnt FROM file_commits GROUP BY file_id
)`).Scan(&n)
	if n == 0 {
		return 1
	}
	return n
}

// DepPresentWithVulns checks if dep_vulnerabilities table has data.
func (s *Store) DepPresentWithVulns() bool {
	present := s.AgentsPresent()
	return present["dep"]
}

// DepModulePresentWithProblems checks if dep_modules has abandoned/bad-license rows.
func (s *Store) DepModulePresentWithProblems() bool {
	if !s.tableExists("dep_modules") {
		return false
	}
	var n int
	s.db.QueryRow(`SELECT COUNT(*) FROM dep_modules WHERE is_abandoned=1 OR license_ok=0`).Scan(&n)
	return n > 0
}

// TableExists is exported for use in signals package.
func (s *Store) TableExists(name string) bool {
	return s.tableExists(name)
}

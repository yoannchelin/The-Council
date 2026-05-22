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

// AgentsPresent checks which agent tables exist and have data.
func (s *Store) AgentsPresent() map[string]bool {
	checks := map[string]string{
		"archaeo":  "SELECT 1 FROM symbols LIMIT 1",
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

type BlastMetric struct {
	Qualified     string
	Path          string
	RiskScore     float64
	FanIn         int
	TransitiveIn  int
}

func (s *Store) BlastMetrics() ([]BlastMetric, error) {
	rows, err := s.db.Query(`
SELECT qualified, path, risk_score, fan_in, transitive_in
FROM blast_metrics`)
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

type SentinelCoverage struct {
	Path            string
	Qualified       string
	DirectTestCount int
}

func (s *Store) SentinelCoverage() ([]SentinelCoverage, error) {
	rows, err := s.db.Query(`
SELECT path, COALESCE(qualified,''), COALESCE(direct_test_count,0)
FROM sentinel_coverage`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SentinelCoverage
	for rows.Next() {
		var c SentinelCoverage
		if err := rows.Scan(&c.Path, &c.Qualified, &c.DirectTestCount); err != nil {
			continue
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ---- hunter_file_stats ----

type HunterFileStat struct {
	Path      string
	BugFixes  int
	FixRatio  float64 // bug-fix commits / total commits
}

func (s *Store) HunterFileStats() ([]HunterFileStat, error) {
	rows, err := s.db.Query(`
SELECT path, COALESCE(bug_fixes,0), COALESCE(fix_ratio,0.0)
FROM hunter_file_stats`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HunterFileStat
	for rows.Next() {
		var h HunterFileStat
		if err := rows.Scan(&h.Path, &h.BugFixes, &h.FixRatio); err != nil {
			continue
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// ---- dep_vulnerabilities ----

type DepVulnerability struct {
	Module   string
	ID       string
	Severity string
	CVSS     float64
	Fixed    bool
	UsedIn   []string // paths that import this module
}

func (s *Store) DepVulnerabilities() ([]DepVulnerability, error) {
	rows, err := s.db.Query(`
SELECT module, vuln_id, COALESCE(severity,''), COALESCE(cvss,0.0), COALESCE(fixed,0)
FROM dep_vulnerabilities`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DepVulnerability
	for rows.Next() {
		var v DepVulnerability
		var fixedInt int
		if err := rows.Scan(&v.Module, &v.ID, &v.Severity, &v.CVSS, &fixedInt); err != nil {
			continue
		}
		v.Fixed = fixedInt == 1
		out = append(out, v)
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
SELECT id FROM council_assessments WHERE repo_path=? ORDER BY created_at DESC LIMIT 1`, repoPath).Scan(&id)
	return id, err
}

// PurgeOldAssessments deletes assessments older than the given Unix timestamp.
func (s *Store) PurgeOldAssessments(olderThan int64) (int64, error) {
	// First collect IDs to delete
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

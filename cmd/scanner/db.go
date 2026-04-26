package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"SentryQ/reporter"
	"SentryQ/utils"

	_ "modernc.org/sqlite"
)

var (
	db     *sql.DB
	dbOnce sync.Once
)

// ScanRecord represents a scan in the database
type ScanRecord struct {
	ID            string     `json:"id"`
	Target        string     `json:"target"`
	SourceType    string     `json:"source_type"` // "upload" or "git"
	Status        string     `json:"status"`      // "running", "completed", "failed", "cancelled"
	Config        string     `json:"config"`      // JSON blob
	CreatedAt     time.Time  `json:"created_at"`
	CompletedAt   *time.Time `json:"completed_at,omitempty"`
	TotalFindings int        `json:"total_findings"`
	CriticalCount int        `json:"critical_count"`
	HighCount     int        `json:"high_count"`
}

// InitDB initializes the SQLite database
func InitDB() error {
	var initErr error
	dbOnce.Do(func() {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			homeDir = "."
		}
		dbDir := filepath.Join(homeDir, ".sentryq")
		if err := os.MkdirAll(dbDir, 0700); err != nil {
			initErr = fmt.Errorf("failed to create database directory %s: %v", dbDir, err)
			return
		}
		dbPath := filepath.Join(dbDir, "scans.db")

		db, err = sql.Open("sqlite", dbPath)
		if err != nil {
			initErr = fmt.Errorf("failed to open database: %v", err)
			return
		}

		// SQLite is single-writer. Allow up to 4 concurrent readers but cap at
		// 4 total open connections to prevent "database is locked" under load.
		// Idle connections are kept warm to avoid repeated open/close overhead.
		db.SetMaxOpenConns(4)
		db.SetMaxIdleConns(4)
		db.SetConnMaxLifetime(0) // connections live as long as the process

		// Apply critical pragmas. WAL mode and busy_timeout are required for safe
		// concurrent access — treat failures as fatal so the app does not start in
		// an unsafe state that silently loses data or deadlocks under concurrent scans.
		criticalPragmas := []string{
			"PRAGMA journal_mode=WAL",
			"PRAGMA busy_timeout=5000",
		}
		for _, pragma := range criticalPragmas {
			if _, err := db.Exec(pragma); err != nil {
				db.Close()
				db = nil
				initErr = fmt.Errorf("critical DB pragma failed (%s): %v — cannot start safely", pragma, err)
				return
			}
		}

		// Enable foreign keys before any schema work.
		if _, err := db.Exec("PRAGMA foreign_keys = ON"); err != nil {
			utils.LogWarn("PRAGMA foreign_keys: " + err.Error())
		}

		// Run versioned migrations. Each migration is applied exactly once and
		// recorded in the schema_migrations table. Adding a new schema change:
		//   1. Append a new migration to the `migrations` slice below.
		//   2. Bump the version number by 1.
		// Never edit or reorder existing migrations — only append.
		if initErr = runMigrations(db); initErr != nil {
			db.Close()
			db = nil
			return
		}

		utils.LogInfo("📦 Database initialized at " + dbPath)
	})
	return initErr
}

// migration holds a single versioned schema change.
type migration struct {
	version int
	sql     string
}

// migrations is the ordered, append-only list of all schema changes.
// Each entry is applied exactly once and recorded in schema_migrations.
// Rule: never edit or reorder an existing entry — only append new ones.
var migrations = []migration{
	{1, `
		CREATE TABLE IF NOT EXISTS scans (
			id TEXT PRIMARY KEY,
			target TEXT NOT NULL,
			source_type TEXT NOT NULL DEFAULT 'upload',
			status TEXT NOT NULL DEFAULT 'running',
			config TEXT DEFAULT '{}',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			completed_at DATETIME,
			total_findings INTEGER DEFAULT 0,
			critical_count INTEGER DEFAULT 0,
			high_count INTEGER DEFAULT 0
		);
		CREATE TABLE IF NOT EXISTS findings (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			scan_id TEXT NOT NULL,
			data TEXT NOT NULL,
			phase TEXT NOT NULL DEFAULT 'final',
			FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
		);
		CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
		CREATE INDEX IF NOT EXISTS idx_findings_phase ON findings(scan_id, phase);
	`},
	// v2 — future schema changes go here, e.g.:
	// {2, `ALTER TABLE scans ADD COLUMN risk_score REAL DEFAULT 0`},
}

// runMigrations creates the schema_migrations tracking table if needed,
// then applies any migrations whose version is higher than the current
// recorded schema version. Each migration runs inside its own transaction
// so a partial failure leaves the database in a consistent state.
func runMigrations(db *sql.DB) error {
	// Bootstrap: create the version-tracking table on first run.
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version INTEGER PRIMARY KEY,
			applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)
	`); err != nil {
		return fmt.Errorf("failed to create schema_migrations table: %w", err)
	}

	// Determine the highest version already applied.
	var currentVersion int
	row := db.QueryRow("SELECT COALESCE(MAX(version), 0) FROM schema_migrations")
	if err := row.Scan(&currentVersion); err != nil {
		return fmt.Errorf("failed to read current schema version: %w", err)
	}

	for _, m := range migrations {
		if m.version <= currentVersion {
			continue // already applied
		}

		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("migration v%d: failed to begin transaction: %w", m.version, err)
		}

		if _, err := tx.Exec(m.sql); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("migration v%d failed: %w", m.version, err)
		}

		if _, err := tx.Exec(
			"INSERT INTO schema_migrations (version) VALUES (?)", m.version,
		); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("migration v%d: failed to record version: %w", m.version, err)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("migration v%d: failed to commit: %w", m.version, err)
		}

		utils.LogInfo(fmt.Sprintf("DB: applied schema migration v%d", m.version))
	}

	return nil
}

// CreateScan inserts a new scan record
func CreateScan(id, target, sourceType, configJSON string) error {
	_, err := db.Exec(
		"INSERT INTO scans (id, target, source_type, config, status, created_at) VALUES (?, ?, ?, ?, 'running', ?)",
		id, target, sourceType, configJSON, time.Now().UTC(),
	)
	return err
}

// UpdateScanStatus updates the status of a scan
func UpdateScanStatus(id, status string) error {
	if status == "completed" || status == "failed" || status == "cancelled" || status == "stopped" {
		now := time.Now().UTC()
		_, err := db.Exec("UPDATE scans SET status = ?, completed_at = ? WHERE id = ?", status, now, id)
		return err
	}
	_, err := db.Exec("UPDATE scans SET status = ? WHERE id = ?", status, id)
	return err
}

// UpdateScanCounts updates the finding counts for a scan
func UpdateScanCounts(id string, total, critical, high int) error {
	_, err := db.Exec(
		"UPDATE scans SET total_findings = ?, critical_count = ?, high_count = ? WHERE id = ?",
		total, critical, high, id,
	)
	return err
}

// SaveFindings stores findings JSON blobs for a scan (replaces any existing 'final' phase findings)
func SaveFindings(scanID string, findings []reporter.Finding) error {
	return SaveFindingsWithPhase(scanID, findings, "final")
}

// SaveFindingsWithPhase stores findings with a specific phase tag ("static", "ai", or "final")
func SaveFindingsWithPhase(scanID string, findings []reporter.Finding, phase string) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}

	// Clear any existing findings for this scan+phase
	rollback := func(e error) error {
		if rbErr := tx.Rollback(); rbErr != nil {
			utils.LogWarn("SaveFindingsWithPhase: rollback failed: " + rbErr.Error())
		}
		return e
	}

	if _, err := tx.Exec("DELETE FROM findings WHERE scan_id = ? AND phase = ?", scanID, phase); err != nil {
		return rollback(err)
	}

	stmt, err := tx.Prepare("INSERT INTO findings (scan_id, data, phase) VALUES (?, ?, ?)")
	if err != nil {
		return rollback(err)
	}
	defer stmt.Close()

	for _, f := range findings {
		data, err := json.Marshal(f)
		if err != nil {
			utils.LogError(fmt.Sprintf("Failed to marshal finding '%s' for scan %s — skipping", f.IssueName, scanID), err)
			continue
		}
		if _, err := stmt.Exec(scanID, string(data), phase); err != nil {
			utils.LogError(fmt.Sprintf("Failed to insert finding for scan %s", scanID), err)
			return rollback(err)
		}
	}

	return tx.Commit()
}

// GetScan retrieves a single scan record
func GetScan(id string) (*ScanRecord, error) {
	row := db.QueryRow("SELECT id, target, source_type, status, config, created_at, completed_at, total_findings, critical_count, high_count FROM scans WHERE id = ?", id)
	var s ScanRecord
	err := row.Scan(&s.ID, &s.Target, &s.SourceType, &s.Status, &s.Config, &s.CreatedAt, &s.CompletedAt, &s.TotalFindings, &s.CriticalCount, &s.HighCount)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// GetAllScans retrieves all scans, most recent first
func GetAllScans() ([]ScanRecord, error) {
	rows, err := db.Query("SELECT id, target, source_type, status, config, created_at, completed_at, total_findings, critical_count, high_count FROM scans ORDER BY created_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scans []ScanRecord
	for rows.Next() {
		var s ScanRecord
		if err := rows.Scan(&s.ID, &s.Target, &s.SourceType, &s.Status, &s.Config, &s.CreatedAt, &s.CompletedAt, &s.TotalFindings, &s.CriticalCount, &s.HighCount); err != nil {
			utils.LogWarn(fmt.Sprintf("GetAllScans: failed to scan row: %v", err))
			continue
		}
		scans = append(scans, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating scan rows: %w", err)
	}
	return scans, nil
}

// GetFindingsForScan retrieves all 'final' phase findings for a scan (backward compatible)
func GetFindingsForScan(scanID string) ([]reporter.Finding, error) {
	return GetFindingsByPhase(scanID, "final")
}

// GetFindingsByPhase retrieves findings for a specific phase
func GetFindingsByPhase(scanID string, phase string) ([]reporter.Finding, error) {
	var rows *sql.Rows
	var err error

	if phase == "" || phase == "final" {
		// Default: return final findings, or all findings if no final phase exists
		rows, err = db.Query("SELECT id, data FROM findings WHERE scan_id = ? AND phase = 'final'", scanID)
		if err != nil {
			return nil, err
		}
	} else {
		rows, err = db.Query("SELECT id, data FROM findings WHERE scan_id = ? AND phase = ?", scanID, phase)
		if err != nil {
			return nil, err
		}
	}
	defer rows.Close()

	var findings []reporter.Finding
	for rows.Next() {
		var id int64
		var data string
		if err := rows.Scan(&id, &data); err != nil {
			utils.LogError(fmt.Sprintf("Failed to scan finding row for scan %s", scanID), err)
			continue
		}
		var f reporter.Finding
		if err := json.Unmarshal([]byte(data), &f); err != nil {
			utils.LogError(fmt.Sprintf("Failed to unmarshal finding id=%d for scan %s", id, scanID), err)
			continue
		}
		// Guard against corrupted or schema-mismatch rows that would produce
		// zero-value findings flowing silently into reports.
		if f.RuleID == "" || f.FilePath == "" {
			utils.LogWarn(fmt.Sprintf("Skipping malformed finding id=%d for scan %s: missing RuleID or FilePath", id, scanID))
			continue
		}
		f.ID = int(id)
		findings = append(findings, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating finding rows for scan %s: %w", scanID, err)
	}

	// Fallback: if phase=final returned nothing AND the scan is no longer
	// running, return all findings regardless of phase (backward-compat for
	// static-only scans that never write a 'final' phase row). Do NOT fall
	// back while the scan is still in progress — that would mix partial
	// intermediate phases and present them as the final result.
	//
	// To avoid a TOCTOU race (scan status changing between the status check and
	// the all-findings query), we re-check the status inside the same query
	// rather than making two separate round-trips.
	if (phase == "" || phase == "final") && len(findings) == 0 {
		var status string
		if err := db.QueryRow("SELECT status FROM scans WHERE id = ?", scanID).Scan(&status); err == nil &&
			status != "running" {
			return getAllFindingsForScan(scanID)
		}
	}

	return findings, nil
}

// getAllFindingsForScan retrieves ALL findings regardless of phase
func getAllFindingsForScan(scanID string) ([]reporter.Finding, error) {
	rows, err := db.Query("SELECT id, data FROM findings WHERE scan_id = ?", scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var findings []reporter.Finding
	for rows.Next() {
		var id int64
		var data string
		if err := rows.Scan(&id, &data); err != nil {
			utils.LogError(fmt.Sprintf("Failed to scan finding row for scan %s", scanID), err)
			continue
		}
		var f reporter.Finding
		if err := json.Unmarshal([]byte(data), &f); err != nil {
			utils.LogError(fmt.Sprintf("Failed to unmarshal finding id=%d for scan %s", id, scanID), err)
			continue
		}
		// Guard against corrupted or schema-mismatch rows that would produce
		// zero-value findings flowing silently into reports.
		if f.RuleID == "" || f.FilePath == "" {
			utils.LogWarn(fmt.Sprintf("Skipping malformed finding id=%d for scan %s: missing RuleID or FilePath", id, scanID))
			continue
		}
		f.ID = int(id)
		findings = append(findings, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating all finding rows for scan %s: %w", scanID, err)
	}
	return findings, nil
}

// UpdateFindingStatus updates the triage status of a specific finding
func UpdateFindingStatus(scanID string, id int, status string) error {
	// 1. Get current finding data
	row := db.QueryRow("SELECT data FROM findings WHERE id = ? AND scan_id = ?", id, scanID)
	var data string
	err := row.Scan(&data)
	if err != nil {
		return err
	}

	// 2. Unmarshal, update status, marshal back
	var f reporter.Finding
	if err := json.Unmarshal([]byte(data), &f); err != nil {
		return err
	}
	f.Status = status

	newData, err := json.Marshal(f)
	if err != nil {
		return err
	}

	// 3. Update in DB
	_, err = db.Exec("UPDATE findings SET data = ? WHERE id = ? AND scan_id = ?", string(newData), id, scanID)
	return err
}

// GetFindingByID fetches a single finding by its DB primary key within a scan.
func GetFindingByID(scanID string, id int) (reporter.Finding, error) {
	var data string
	err := db.QueryRow("SELECT data FROM findings WHERE id = ? AND scan_id = ?", id, scanID).Scan(&data)
	if err != nil {
		return reporter.Finding{}, err
	}
	var f reporter.Finding
	if err := json.Unmarshal([]byte(data), &f); err != nil {
		return reporter.Finding{}, err
	}
	f.ID = id
	return f, nil
}

// DeleteScan removes a scan and its findings
func DeleteScan(id string) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	rollback := func(e error) error {
		if rbErr := tx.Rollback(); rbErr != nil {
			utils.LogWarn("DeleteScan: rollback failed: " + rbErr.Error())
		}
		return e
	}

	if _, err := tx.Exec("DELETE FROM findings WHERE scan_id = ?", id); err != nil {
		return rollback(err)
	}
	if _, err := tx.Exec("DELETE FROM scans WHERE id = ?", id); err != nil {
		return rollback(err)
	}
	return tx.Commit()
}

// CloseDB closes the database connection cleanly
func CloseDB() error {
	if db != nil {
		err := db.Close()
		if err == nil {
			utils.LogInfo("Database connection closed cleanly.")
		} else {
			utils.LogError("Error closing database connection", err)
		}
		return err
	}
	return nil
}

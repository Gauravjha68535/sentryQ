package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

		// Set pragmas via SQL rather than DSN URL parameters so the behaviour is
		// consistent across modernc.org/sqlite versions (URL pragma syntax is
		// undocumented and may change between minor releases).
		for _, pragma := range []string{
			"PRAGMA journal_mode=WAL",
			"PRAGMA busy_timeout=5000",
		} {
			if _, err := db.Exec(pragma); err != nil {
				utils.LogWarn(fmt.Sprintf("db: %s failed: %v", pragma, err))
			}
		}

		// Create tables
		schema := `
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
		`
		_, err = db.Exec(schema)
		if err != nil {
			initErr = fmt.Errorf("failed to create schema: %v", err)
			return
		}

		// Enable foreign keys
		if _, err := db.Exec("PRAGMA foreign_keys = ON"); err != nil {
			utils.LogWarn("PRAGMA foreign_keys: " + err.Error())
		}

		// Add phase column if it doesn't exist (migration for existing DBs)
		// Ignore "duplicate column" errors — that just means the migration already ran.
		if _, err := db.Exec("ALTER TABLE findings ADD COLUMN phase TEXT NOT NULL DEFAULT 'final'"); err != nil {
			if !strings.Contains(err.Error(), "duplicate column") {
				utils.LogWarn("ALTER TABLE findings (phase): " + err.Error())
			}
		}

		// Create phase index (safe to run after column is guaranteed to exist)
		if _, err := db.Exec("CREATE INDEX IF NOT EXISTS idx_findings_phase ON findings(scan_id, phase)"); err != nil {
			utils.LogWarn("CREATE INDEX idx_findings_phase: " + err.Error())
		}

		utils.LogInfo("📦 Database initialized at " + dbPath)
	})
	return initErr
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
	if (phase == "" || phase == "final") && len(findings) == 0 {
		scan, scanErr := GetScan(scanID)
		if scanErr == nil && scan.Status != "running" {
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

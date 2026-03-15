package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"QWEN_SCR_24_FEB_2026/reporter"
	"QWEN_SCR_24_FEB_2026/utils"

	_ "github.com/mattn/go-sqlite3"
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
		dbDir := filepath.Join(homeDir, ".qwen-scanner")
		os.MkdirAll(dbDir, 0755)
		dbPath := filepath.Join(dbDir, "scans.db")

		db, err = sql.Open("sqlite3", dbPath+"?_journal_mode=WAL&_busy_timeout=5000")
		if err != nil {
			initErr = fmt.Errorf("failed to open database: %v", err)
			return
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
		db.Exec("PRAGMA foreign_keys = ON")

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
	if status == "completed" || status == "failed" || status == "cancelled" {
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

// SaveFindings stores findings JSON blobs for a scan (replaces any existing findings)
func SaveFindings(scanID string, findings []reporter.Finding) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}

	// Clear any existing findings for this scan to prevent duplicates
	if _, err := tx.Exec("DELETE FROM findings WHERE scan_id = ?", scanID); err != nil {
		tx.Rollback()
		return err
	}

	stmt, err := tx.Prepare("INSERT INTO findings (scan_id, data) VALUES (?, ?)")
	if err != nil {
		tx.Rollback()
		return err
	}
	defer stmt.Close()

	for _, f := range findings {
		data, err := json.Marshal(f)
		if err != nil {
			continue
		}
		if _, err := stmt.Exec(scanID, string(data)); err != nil {
			utils.LogError(fmt.Sprintf("Failed to insert finding for scan %s", scanID), err)
			tx.Rollback()
			return err
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
			continue
		}
		scans = append(scans, s)
	}
	return scans, nil
}

// GetFindings retrieves all findings for a scan
func GetFindingsForScan(scanID string) ([]reporter.Finding, error) {
	rows, err := db.Query("SELECT data FROM findings WHERE scan_id = ?", scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var findings []reporter.Finding
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			continue
		}
		var f reporter.Finding
		if err := json.Unmarshal([]byte(data), &f); err != nil {
			continue
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// DeleteScan removes a scan and its findings
func DeleteScan(id string) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	tx.Exec("DELETE FROM findings WHERE scan_id = ?", id)
	tx.Exec("DELETE FROM scans WHERE id = ?", id)
	return tx.Commit()
}

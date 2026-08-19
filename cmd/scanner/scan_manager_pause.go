package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	"SentryQ/utils"
)

// PauseControl manages pause/resume state for an active scan.
type PauseControl struct {
	mu       sync.Mutex
	paused   bool
	resumeCh chan struct{}
}

// Wait blocks if the scan is paused, returning when resumed or ctx is done.
// Returns false if ctx was cancelled (scan should stop).
func (pc *PauseControl) Wait(ctx context.Context) bool {
	pc.mu.Lock()
	if !pc.paused {
		pc.mu.Unlock()
		return ctx.Err() == nil
	}
	ch := pc.resumeCh
	pc.mu.Unlock()
	select {
	case <-ch:
		return ctx.Err() == nil
	case <-ctx.Done():
		return false
	}
}

var (
	pauseControls   = make(map[string]*PauseControl)
	pauseControlsMu sync.Mutex
)

func registerPauseControl(scanID string) {
	pc := &PauseControl{}
	pauseControlsMu.Lock()
	pauseControls[scanID] = pc
	pauseControlsMu.Unlock()
}

func unregisterPauseControl(scanID string) {
	pauseControlsMu.Lock()
	delete(pauseControls, scanID)
	pauseControlsMu.Unlock()
}

func getPauseControl(scanID string) *PauseControl {
	pauseControlsMu.Lock()
	pc := pauseControls[scanID]
	pauseControlsMu.Unlock()
	return pc
}

// getScanTimeout returns the maximum scan duration.
// Override the default 60-minute cap with SENTRYQ_SCAN_TIMEOUT_MINUTES env var.
func getScanTimeout() time.Duration {
	if v := os.Getenv("SENTRYQ_SCAN_TIMEOUT_MINUTES"); v != "" {
		if mins, err := strconv.Atoi(v); err == nil && mins > 0 {
			return time.Duration(mins) * time.Minute
		}
	}
	return 60 * time.Minute
}

// checkPause blocks if the scan is paused. Returns false if ctx was cancelled.
func checkPause(scanID string, ctx context.Context) bool {
	pc := getPauseControl(scanID)
	if pc == nil {
		return ctx.Err() == nil
	}
	return pc.Wait(ctx)
}

// PauseScan pauses an active scan between phases.
func PauseScan(scanID string) error {
	pc := getPauseControl(scanID)
	if pc == nil {
		return fmt.Errorf("scan %s not found or not active", scanID)
	}
	pc.mu.Lock()
	defer pc.mu.Unlock()
	if pc.paused {
		return nil
	}
	pc.paused = true
	pc.resumeCh = make(chan struct{})
	if err := UpdateScanStatus(scanID, "paused"); err != nil {
		utils.LogError(fmt.Sprintf("Failed to update scan %s status to paused", scanID), err)
	}
	wsHub.BroadcastLog(scanID, "⏸ Scan paused by user", "warning")
	wsHub.Broadcast(scanID, WSMessage{Type: "paused"})
	return nil
}

// ResumeScan resumes a paused scan.
func ResumeScan(scanID string) error {
	pc := getPauseControl(scanID)
	if pc == nil {
		return fmt.Errorf("scan %s not found or not active", scanID)
	}
	pc.mu.Lock()
	defer pc.mu.Unlock()
	if !pc.paused {
		return nil
	}
	pc.paused = false
	close(pc.resumeCh)
	if err := UpdateScanStatus(scanID, "running"); err != nil {
		utils.LogError(fmt.Sprintf("Failed to update scan %s status to running", scanID), err)
	}
	wsHub.BroadcastLog(scanID, "▶ Scan resumed", "success")
	wsHub.Broadcast(scanID, WSMessage{Type: "resumed"})
	return nil
}

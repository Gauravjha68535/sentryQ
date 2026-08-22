package ai

import (
	"math"
	"testing"
)

func TestLaplaceSmoothingFirstSample(t *testing.T) {
	c := NewConfidenceCalibrator()
	// Before any observations, raw confidence passes through
	raw := 0.8
	got := c.CalibrateConfidence("critical", raw)
	if got != raw {
		t.Errorf("no observations: expected raw %f, got %f", raw, got)
	}

	// After 1 TP observation, smoothed accuracy = (1+1)/(1+2) = 0.667
	// calibrated = 0.8*0.7 + 0.667*0.3 = 0.56 + 0.2 = 0.76
	c.RecordValidation("critical", true)
	got = c.CalibrateConfidence("critical", raw)
	if got <= 0 || got > 1 {
		t.Errorf("calibrated confidence out of range [0,1]: %f", got)
	}
	// Must not be zero or 1.0 exactly (clipped at 0.99)
	if got == 0 || got >= 1.0 {
		t.Errorf("unexpected boundary value: %f", got)
	}
}

func TestLaplaceSmoothingConvergence(t *testing.T) {
	c := NewConfidenceCalibrator()
	// After many TPs, accuracy should converge to ~1.0 (but stay < 0.99 clip)
	for i := 0; i < 100; i++ {
		c.RecordValidation("high", true)
	}
	got := c.CalibrateConfidence("high", 0.9)
	if got < 0.85 {
		t.Errorf("after 100 TPs, calibrated confidence should be high, got %f", got)
	}
}

func TestLaplaceSmoothingHighFPRate(t *testing.T) {
	c := NewConfidenceCalibrator()
	// All FPs — accuracy converges to ~0
	for i := 0; i < 20; i++ {
		c.RecordValidation("medium", false)
	}
	got := c.CalibrateConfidence("medium", 0.8)
	// Calibrated should be lower than raw when FP rate is high
	if got >= 0.8 {
		t.Errorf("high FP rate should lower calibrated confidence below raw, got %f", got)
	}
}

func TestLaplaceSmoothingNotZeroOrOne(t *testing.T) {
	c := NewConfidenceCalibrator()
	// Single observation — without Laplace, 1/1=1.0 or 0/1=0.0. With Laplace it's bounded.
	c.RecordValidation("low", true)
	got := c.CalibrateConfidence("low", 0.5)
	if math.Abs(got-1.0) < 1e-9 || math.Abs(got) < 1e-9 {
		t.Errorf("Laplace smoothing should prevent 0 or 1 after single observation, got %f", got)
	}
}

func TestRecordOutcomeDifferentSeverities(t *testing.T) {
	c := NewConfidenceCalibrator()
	c.RecordValidation("critical", true)
	c.RecordValidation("high", false)
	c.RecordValidation("medium", true)

	// Each severity is calibrated independently — should not panic
	for _, sev := range []string{"critical", "high", "medium", "low"} {
		got := c.CalibrateConfidence(sev, 0.75)
		if got < 0 || got > 1 {
			t.Errorf("severity %s: calibrated confidence %f out of [0,1]", sev, got)
		}
	}
}

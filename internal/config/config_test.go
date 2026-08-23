package config

import (
	"testing"
	"time"
)

func TestParseRunUsesRealtimeReportingIntervals(t *testing.T) {
	cfg, err := Parse([]string{"run"}, "test")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.TrafficInterval != time.Second {
		t.Fatalf("TrafficInterval = %s, want 1s", cfg.TrafficInterval)
	}
	if cfg.HeartbeatInterval != 5*time.Second {
		t.Fatalf("HeartbeatInterval = %s, want 5s", cfg.HeartbeatInterval)
	}
	if cfg.AccessInterval != 15*time.Second {
		t.Fatalf("AccessInterval = %s, want 15s", cfg.AccessInterval)
	}
}

func TestParseRunRejectsTooFrequentAccessWrites(t *testing.T) {
	if _, err := Parse([]string{"run", "--access-interval=9s"}, "test"); err == nil {
		t.Fatal("Parse accepted an access interval below 10 seconds")
	}
}

func TestParseRunRejectsSubsecondTrafficInterval(t *testing.T) {
	if _, err := Parse([]string{"run", "--traffic-interval=500ms"}, "test"); err == nil {
		t.Fatal("Parse accepted a subsecond traffic interval")
	}
}

package main

import (
	"strings"
	"testing"
	"time"
)

// Verifies GetNodeBatteryHistory reads node_metrics (out-of-band node telemetry,
// e.g. polled repeater voltage) for non-observer nodes, and merges it with
// observer_metrics when both exist.
func TestGetNodeBatteryHistory_MergesNodeMetrics(t *testing.T) {
	db := setupTestDB(t)
	now := time.Now().UTC()

	// node_metrics is created by the ingestor migration in prod; create it here.
	if _, err := db.conn.Exec(`
		CREATE TABLE IF NOT EXISTS node_metrics (
			pubkey        TEXT NOT NULL,
			timestamp     TEXT NOT NULL,
			battery_mv    INTEGER,
			temperature_c REAL,
			PRIMARY KEY (pubkey, timestamp)
		)`); err != nil {
		t.Fatal(err)
	}

	pk := "6159884d2f8364138bb2e4b626d53faa"
	db.conn.Exec(`INSERT INTO nodes (public_key, name, role, last_seen, first_seen) VALUES (?, 'RoofRPT', 'repeater', ?, ?)`,
		pk, now.Format(time.RFC3339), now.Add(-72*time.Hour).Format(time.RFC3339))

	// Pure repeater: telemetry only in node_metrics (no observer row).
	for i, mv := range []int{4290, 4270} {
		ts := now.Add(time.Duration(-2+i) * time.Hour).Format(time.RFC3339)
		db.conn.Exec(`INSERT INTO node_metrics (pubkey, timestamp, battery_mv) VALUES (?, ?, ?)`, pk, ts, mv)
	}

	since := now.Add(-24 * time.Hour).Format(time.RFC3339)
	samples, err := db.GetNodeBatteryHistory(pk, since)
	if err != nil {
		t.Fatalf("GetNodeBatteryHistory (node_metrics only): %v", err)
	}
	if len(samples) != 2 {
		t.Fatalf("expected 2 node_metrics samples, got %d (%+v)", len(samples), samples)
	}

	// Same key also appears as an observer sample -> merged into one series.
	idUpper := strings.ToUpper(pk)
	db.conn.Exec(`INSERT INTO observers (id, name, last_seen, first_seen) VALUES (?, 'RoofRPT', ?, ?)`,
		idUpper, now.Format(time.RFC3339), now.Add(-72*time.Hour).Format(time.RFC3339))
	db.conn.Exec(`INSERT INTO observer_metrics (observer_id, timestamp, battery_mv) VALUES (?, ?, ?)`,
		idUpper, now.Add(-30*time.Minute).Format(time.RFC3339), 4300)

	merged, err := db.GetNodeBatteryHistory(pk, since)
	if err != nil {
		t.Fatalf("GetNodeBatteryHistory (merged): %v", err)
	}
	if len(merged) != 3 {
		t.Fatalf("expected 3 merged samples, got %d (%+v)", len(merged), merged)
	}
	for i := 1; i < len(merged); i++ {
		if merged[i].Timestamp < merged[i-1].Timestamp {
			t.Errorf("samples not ordered ascending: %+v", merged)
		}
	}
}

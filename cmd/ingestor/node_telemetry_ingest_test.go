package main

import "testing"

// Verifies the out-of-band node-telemetry ingest path: migration columns/table,
// UpdateNodeTelemetryAt (current value + freshness) and InsertNodeMetrics (history).
func TestNodeTelemetryIngest(t *testing.T) {
	s, err := OpenStore(tempDBPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	pk := "6159884d2f8364138bb2e4b626d53faa8f788c43994723354a3621cf35cb87a6"
	if err := s.UpsertNode(pk, "TestRPT", "repeater", nil, nil, "2026-09-15T18:00:00Z"); err != nil {
		t.Fatalf("UpsertNode: %v", err)
	}

	mv := 4290
	temp := 35.0
	ts := "2026-09-15T18:40:00Z"
	if err := s.UpdateNodeTelemetryAt(pk, &mv, &temp, ts); err != nil {
		t.Fatalf("UpdateNodeTelemetryAt: %v", err)
	}
	if err := s.InsertNodeMetrics(pk, ts, &mv, &temp); err != nil {
		t.Fatalf("InsertNodeMetrics: %v", err)
	}

	var gotMv int
	var gotTemp float64
	var gotTs string
	if err := s.db.QueryRow(`SELECT battery_mv, temperature_c, telemetry_updated_at FROM nodes WHERE public_key=?`, pk).Scan(&gotMv, &gotTemp, &gotTs); err != nil {
		t.Fatalf("read nodes: %v", err)
	}
	if gotMv != mv || gotTemp != temp || gotTs != ts {
		t.Fatalf("nodes telemetry mismatch: mv=%d temp=%v ts=%s", gotMv, gotTemp, gotTs)
	}

	var cnt int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM node_metrics WHERE pubkey=? AND battery_mv=? AND timestamp=?`, pk, mv, ts).Scan(&cnt); err != nil {
		t.Fatalf("read node_metrics: %v", err)
	}
	if cnt != 1 {
		t.Fatalf("expected 1 node_metrics row, got %d", cnt)
	}

	// INSERT OR REPLACE: same (pubkey, timestamp) must not duplicate.
	if err := s.InsertNodeMetrics(pk, ts, &mv, &temp); err != nil {
		t.Fatalf("InsertNodeMetrics rerun: %v", err)
	}
	var cnt2 int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM node_metrics WHERE pubkey=?`, pk).Scan(&cnt2); err != nil {
		t.Fatalf("count node_metrics: %v", err)
	}
	if cnt2 != 1 {
		t.Fatalf("expected 1 row after replace, got %d", cnt2)
	}
}

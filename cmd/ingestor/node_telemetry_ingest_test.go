package main

import (
	"strings"
	"testing"
)

// Verifies the out-of-band node-telemetry ingest path: migration columns/table,
// UpdateNodeTelemetryAt (current value) and InsertNodeMetrics (history).
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
	if err := s.UpdateNodeTelemetryAt(pk, &mv, &temp); err != nil {
		t.Fatalf("UpdateNodeTelemetryAt: %v", err)
	}
	if err := s.InsertNodeMetrics(pk, ts, &mv, &temp); err != nil {
		t.Fatalf("InsertNodeMetrics: %v", err)
	}

	var gotMv int
	var gotTemp float64
	if err := s.db.QueryRow(`SELECT battery_mv, temperature_c FROM nodes WHERE public_key=?`, pk).Scan(&gotMv, &gotTemp); err != nil {
		t.Fatalf("read nodes: %v", err)
	}
	if gotMv != mv || gotTemp != temp {
		t.Fatalf("nodes telemetry mismatch: mv=%d temp=%v", gotMv, gotTemp)
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

// tableColumns returns the column names of a table in declaration order.
func tableColumns(t *testing.T, s *Store, table string) []string {
	t.Helper()
	rows, err := s.db.Query(`SELECT name FROM pragma_table_info(?) ORDER BY cid`, table)
	if err != nil {
		t.Fatalf("table_info %s: %v", table, err)
	}
	defer rows.Close()
	var cols []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		cols = append(cols, n)
	}
	return cols
}

// MoveStaleNodes copies with SELECT *, so the node-telemetry schema must leave
// nodes and inactive_nodes with identical columns in identical order, and a
// node that received out-of-band telemetry must still move.
func TestNodeTelemetryKeepsStaleNodeMoveWorking(t *testing.T) {
	s, err := OpenStore(tempDBPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	a, b := tableColumns(t, s, "nodes"), tableColumns(t, s, "inactive_nodes")
	if strings.Join(a, ",") != strings.Join(b, ",") {
		t.Fatalf("nodes and inactive_nodes differ:\n nodes:    %v\n inactive: %v", a, b)
	}

	pk := "6159884d2f8364138bb2e4b626d53faa8f788c43994723354a3621cf35cb87a6"
	if err := s.UpsertNode(pk, "OldRPT", "repeater", nil, nil, "2020-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	mv := 3900
	if err := s.UpdateNodeTelemetryAt(pk, &mv, nil); err != nil {
		t.Fatal(err)
	}
	moved, err := s.MoveStaleNodes(7)
	if err != nil {
		t.Fatalf("MoveStaleNodes: %v", err)
	}
	if moved != 1 {
		t.Fatalf("expected 1 node moved, got %d", moved)
	}
	var gotMv int
	if err := s.db.QueryRow(`SELECT battery_mv FROM inactive_nodes WHERE public_key=?`, pk).Scan(&gotMv); err != nil {
		t.Fatalf("read inactive_nodes: %v", err)
	}
	if gotMv != mv {
		t.Fatalf("battery_mv not carried over: got %d want %d", gotMv, mv)
	}
}

// A database written by the earlier build of this branch has
// nodes.telemetry_updated_at as an extra trailing column. Reopening it must drop
// that column so the tables line up again and stale nodes move.
func TestNodeTelemetryFreshnessColumnDroppedOnUpgrade(t *testing.T) {
	path := tempDBPath(t)
	s, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`ALTER TABLE nodes ADD COLUMN telemetry_updated_at TEXT`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`DELETE FROM _migrations WHERE name = 'node_telemetry_freshness_drop_v1'`); err != nil {
		t.Fatal(err)
	}
	pk := "aabbccdd00000000000000000000000000000000000000000000000000000001"
	if err := s.UpsertNode(pk, "Legacy", "repeater", nil, nil, "2020-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.MoveStaleNodes(7); err == nil {
		t.Fatal("precondition: expected MoveStaleNodes to fail with the extra column")
	}
	s.Close()

	s, err = OpenStore(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s.Close()
	for _, c := range tableColumns(t, s, "nodes") {
		if c == "telemetry_updated_at" {
			t.Fatal("nodes.telemetry_updated_at still present after upgrade")
		}
	}
	moved, err := s.MoveStaleNodes(7)
	if err != nil {
		t.Fatalf("MoveStaleNodes after upgrade: %v", err)
	}
	if moved != 1 {
		t.Fatalf("expected 1 node moved, got %d", moved)
	}
}

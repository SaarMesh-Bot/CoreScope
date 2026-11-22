package main

import (
	"fmt"
	"testing"
	"time"

	"github.com/meshcore-analyzer/packetpath"
)

// Positions used below (Saarland-ish, ~10-40 km apart). far is ~300 km away.
var (
	plSaarbruecken = [2]float64{49.2402, 6.9969}
	plVoelklingen  = [2]float64{49.2526, 6.8590}
	plMerzig       = [2]float64{49.4436, 6.6380}
	plStIngbert    = [2]float64{49.2770, 7.1120}
	plFar          = [2]float64{51.9607, 7.6261} // Münster
)

func plNode(pk string, pos [2]float64) nodeInfo {
	return nodeInfo{Role: "repeater", PublicKey: pk, Name: pk, Lat: pos[0], Lon: pos[1], HasGPS: true}
}

func plGeo(nodes []nodeInfo) map[string]nodeGeoInfo {
	g := make(map[string]nodeGeoInfo, len(nodes))
	for _, n := range nodes {
		g[n.PublicKey] = nodeGeoInfo{Lat: n.Lat, Lon: n.Lon, HasGPS: n.HasGPS}
	}
	return g
}

func plFind(links []*PathLink, a, b string) *PathLink {
	k := makeEdgeKey(a, b)
	for _, l := range links {
		if l.NodeA == k.A && l.NodeB == k.B {
			return l
		}
	}
	return nil
}

func TestResolvePathHopsForLinks_UniquePrefixes(t *testing.T) {
	nodes := []nodeInfo{
		plNode("aa11aa11", plSaarbruecken),
		plNode("bb22bb22", plVoelklingen),
		plNode("cc33cc33", plMerzig),
	}
	pm := buildPrefixMap(nodes)
	pks, viaGeo := resolvePathHopsForLinks([]string{"aa", "bb", "cc"}, "", "", pm, plGeo(nodes), nil)
	want := []string{"aa11aa11", "bb22bb22", "cc33cc33"}
	for i := range want {
		if pks[i] != want[i] || viaGeo[i] {
			t.Fatalf("hop %d: got %q geo=%v, want %q unique", i, pks[i], viaGeo[i], want[i])
		}
	}
}

func TestResolvePathHopsForLinks_GeoDisambiguation(t *testing.T) {
	// Prefix "bb" is shared by a node near Völklingen and one in Münster.
	// Its neighbours (aa near Saarbrücken, cc near Merzig) are located, so
	// only the Völklingen node fits.
	nodes := []nodeInfo{
		plNode("aa11aa11", plSaarbruecken),
		plNode("bb22bb22", plVoelklingen),
		plNode("bbffbbff", plFar),
		plNode("cc33cc33", plMerzig),
	}
	pm := buildPrefixMap(nodes)
	pks, viaGeo := resolvePathHopsForLinks([]string{"aa", "bb", "cc"}, "", "", pm, plGeo(nodes), nil)
	if pks[1] != "bb22bb22" || !viaGeo[1] {
		t.Fatalf("hop 1: got %q geo=%v, want bb22bb22 via geo", pks[1], viaGeo[1])
	}
}

func TestResolvePathHopsForLinks_GeoTwoFitsStaysUnresolved(t *testing.T) {
	// Both "bb" candidates are within reach of the neighbours: no guess.
	nodes := []nodeInfo{
		plNode("aa11aa11", plSaarbruecken),
		plNode("bb22bb22", plVoelklingen),
		plNode("bbffbbff", plStIngbert),
		plNode("cc33cc33", plMerzig),
	}
	pm := buildPrefixMap(nodes)
	pks, _ := resolvePathHopsForLinks([]string{"aa", "bb", "cc"}, "", "", pm, plGeo(nodes), nil)
	if pks[1] != "" {
		t.Fatalf("hop 1: got %q, want unresolved (two candidates fit)", pks[1])
	}
}

func TestResolvePathHopsForLinks_NoLocatedAnchorStaysUnresolved(t *testing.T) {
	// The ambiguous hop's neighbours are unknown prefixes: nothing anchors it.
	nodes := []nodeInfo{
		plNode("bb22bb22", plVoelklingen),
		plNode("bbffbbff", plFar),
	}
	pm := buildPrefixMap(nodes)
	pks, _ := resolvePathHopsForLinks([]string{"11", "bb", "22"}, "", "", pm, plGeo(nodes), nil)
	if pks[1] != "" {
		t.Fatalf("hop 1: got %q, want unresolved", pks[1])
	}
}

func TestResolvePathHopsForLinks_ObserverAnchorsLastHop(t *testing.T) {
	// The last hop is ambiguous; the located observer anchors it.
	nodes := []nodeInfo{
		plNode("aa11aa11", plMerzig),
		plNode("bb22bb22", plVoelklingen),
		plNode("bbffbbff", plFar),
		plNode("0b5e0b5e", plSaarbruecken), // observer
	}
	pm := buildPrefixMap(nodes)
	pks, viaGeo := resolvePathHopsForLinks([]string{"aa", "bb"}, "", "0b5e0b5e", pm, plGeo(nodes), nil)
	if pks[1] != "bb22bb22" || !viaGeo[1] {
		t.Fatalf("last hop: got %q geo=%v, want bb22bb22 via geo", pks[1], viaGeo[1])
	}
}

func TestResolvePathHopsForLinks_RepeatedNodeDropped(t *testing.T) {
	// "aa" resolves uniquely at two positions: the prefix belongs to a node
	// we do not know as well, so both positions are dropped.
	nodes := []nodeInfo{
		plNode("aa11aa11", plSaarbruecken),
		plNode("bb22bb22", plVoelklingen),
	}
	pm := buildPrefixMap(nodes)
	pks, _ := resolvePathHopsForLinks([]string{"aa", "bb", "aa"}, "", "", pm, plGeo(nodes), nil)
	if pks[0] != "" || pks[2] != "" || pks[1] != "bb22bb22" {
		t.Fatalf("got %v, want [\"\" bb22bb22 \"\"]", pks)
	}
}

func TestResolvePathHopsForLinks_PathTrust(t *testing.T) {
	nodes := []nodeInfo{
		plNode("aa11aa11", plSaarbruecken),
		plNode("bb22bb22", plVoelklingen),
	}
	pm := buildPrefixMap(nodes)
	trust := &packetpath.TrustConfig{MinHashBytesForMapping: 2}
	pks, _ := resolvePathHopsForLinks([]string{"aa", "bb22"}, "", "", pm, plGeo(nodes), trust)
	if pks[0] != "" || pks[1] != "bb22bb22" {
		t.Fatalf("got %v, want 1-byte hop untrusted", pks)
	}
}

func TestBuildNeighborGraph_PathLinksMidPath(t *testing.T) {
	// ADVERT from X, path [R1,R2,R3], heard by O. Neighbor edges: X↔R1 and
	// O↔R3. Path links: R1↔R2, R2↔R3. Neither kind leaks into the other.
	nodes := []nodeInfo{
		plNode("ffff0000", plMerzig), // originator X
		plNode("a1a1a1a1", plMerzig),
		plNode("b2b2b2b2", plVoelklingen),
		plNode("c3c3c3c3", plSaarbruecken),
		plNode("0b5e0b5e", plStIngbert), // observer
	}
	tx := ngMakeTx(1, 4, ngFromNodeJSON("ffff0000"), []*StoreObs{
		ngMakeObs("0b5e0b5e", `["a1","b2","c3"]`, nowStr, nil),
	})
	g := BuildFromStore(ngTestStore(nodes, []*StoreTx{tx}))

	if n := len(g.AllEdges()); n != 2 {
		t.Fatalf("neighbor edges: got %d, want 2 (path links must not leak in)", n)
	}
	links := g.PathLinks()
	if len(links) != 2 {
		t.Fatalf("path links: got %d, want 2", len(links))
	}
	for _, pair := range [][2]string{{"a1a1a1a1", "b2b2b2b2"}, {"b2b2b2b2", "c3c3c3c3"}} {
		l := plFind(links, pair[0], pair[1])
		if l == nil {
			t.Fatalf("missing path link %s↔%s", pair[0], pair[1])
		}
		if l.Count != 1 || l.HashBytes[1] != 1 || !l.Observers["0b5e0b5e"] {
			t.Errorf("%s↔%s: count=%d hashBytes=%v observers=%v", pair[0], pair[1], l.Count, l.HashBytes, l.Observers)
		}
	}
}

func TestBuildNeighborGraph_PathLinksCountOncePerTransmission(t *testing.T) {
	// Two observers hear the same transmission over the same mid-path
	// relays: the link counts once, with both observers.
	nodes := []nodeInfo{
		plNode("a1a1a1a1", plMerzig),
		plNode("b2b2b2b2", plVoelklingen),
		plNode("c3c3c3c3", plSaarbruecken),
		plNode("0b5e0001", plStIngbert),
		plNode("0b5e0002", plSaarbruecken),
	}
	tx := ngMakeTx(1, 2, ngFromNodeJSON("a1a1a1a1"), []*StoreObs{
		ngMakeObs("0b5e0001", `["a1","b2","c3"]`, nowStr, nil),
		ngMakeObs("0b5e0002", `["a1","b2"]`, nowStr, nil),
	})
	tx2 := ngMakeTx(2, 2, ngFromNodeJSON("a1a1a1a1"), []*StoreObs{
		ngMakeObs("0b5e0001", `["a1","b2"]`, nowStr, nil),
	})
	g := BuildFromStore(ngTestStore(nodes, []*StoreTx{tx, tx2}))
	l := plFind(g.PathLinks(), "a1a1a1a1", "b2b2b2b2")
	if l == nil {
		t.Fatal("missing a1↔b2")
	}
	if l.Count != 2 {
		t.Errorf("count: got %d, want 2 (one per transmission)", l.Count)
	}
	if len(l.Observers) != 2 {
		t.Errorf("observers: got %d, want 2", len(l.Observers))
	}
}

func TestBuildNeighborGraph_PathLinksRejectFarHop(t *testing.T) {
	nodes := []nodeInfo{
		plNode("a1a1a1a1", plSaarbruecken),
		plNode("b2b2b2b2", plFar),
	}
	tx := ngMakeTx(1, 2, "{}", []*StoreObs{ngMakeObs("0b5e0001", `["a1","b2"]`, nowStr, nil)})
	g := BuildFromStore(ngTestStore(nodes, []*StoreTx{tx}))
	if n := len(g.PathLinks()); n != 0 {
		t.Fatalf("got %d path links, want 0 (hop > %v km)", n, pathLinkMaxHopKm)
	}
}

func TestPathLink_ScoreAndHashFilter(t *testing.T) {
	l := &PathLink{Count: 10, LastSeen: time.Now(), HashBytes: map[int]int{1: 6, 2: 3, 3: 1}}
	if s := l.Score(time.Now()); s < 0.49 || s > 0.51 {
		t.Errorf("score: got %v, want ~0.5", s)
	}
	if n := l.countAtLeastBytes(2); n != 4 {
		t.Errorf("≥2 bytes: got %d, want 4", n)
	}
	if n := l.countAtLeastBytes(1); n != 10 {
		t.Errorf("≥1 byte: got %d, want 10", n)
	}
}

func TestComputePathLinks_Filters(t *testing.T) {
	nodes := []nodeInfo{
		plNode("a1a1a1a1", plMerzig),
		plNode("b2b2b2b2", plVoelklingen),
		plNode("c3c3c3c3", plSaarbruecken),
	}
	var txs []*StoreTx
	for i := 0; i < 3; i++ {
		txs = append(txs, ngMakeTx(i+1, 2, "{}", []*StoreObs{
			ngMakeObs("0b5e0001", `["a1a1","b2b2"]`, nowStr, nil),
		}))
	}
	txs = append(txs, ngMakeTx(9, 2, "{}", []*StoreObs{
		ngMakeObs("0b5e0001", `["b2","c3"]`, nowStr, nil),
	}))
	srv := &Server{store: ngTestStore(nodes, txs)}

	r := srv.computePathLinks(1, 1, 100)
	if r.Total != 2 || r.Links[0].Count != 3 {
		t.Fatalf("all: %+v", r)
	}
	if r := srv.computePathLinks(2, 1, 100); r.Total != 1 {
		t.Errorf("min_count=2: got %d links, want 1", r.Total)
	}
	r = srv.computePathLinks(1, 2, 100)
	if r.Total != 1 || r.Links[0].Source != "a1a1a1a1" {
		t.Errorf("min_hash_bytes=2: %+v", r)
	}
	if r := srv.computePathLinks(1, 1, 1); len(r.Links) != 1 || r.Total != 2 {
		t.Errorf("limit=1: got %d links, total %d", len(r.Links), r.Total)
	}
}

// BenchmarkResolvePathHopsForLinks: one 8-hop, 1-byte path over a mesh of
// 1200 nodes (every prefix shared ~5 ways).
func BenchmarkResolvePathHopsForLinks(b *testing.B) {
	var nodes []nodeInfo
	for i := 0; i < 1200; i++ {
		pos := [2]float64{49.0 + float64(i%40)*0.02, 6.5 + float64(i/40)*0.02}
		nodes = append(nodes, plNode(fmt.Sprintf("%02x%06x", i%240, i), pos))
	}
	pm := buildPrefixMap(nodes)
	geo := plGeo(nodes)
	path := []string{"01", "17", "2a", "33", "4c", "51", "6e", "70"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resolvePathHopsForLinks(path, "", "00000000", pm, geo, nil)
	}
}

package main

// Path links: hop↔hop links taken from the middle of packet paths.
//
// The neighbor graph (neighbor_graph.go) only takes the two ends of a path
// as evidence: originator↔path[0] (ADVERT / ANON_REQ) and
// observer↔path[last]. Every pair of consecutive relays in the middle of a
// flood path, path[i]↔path[i+1], is a link the packet actually travelled,
// but it is left out because both ends are hop prefixes and a wrong guess on
// either side manufactures a false edge.
//
// This file records those mid-path links in a SEPARATE set on the graph
// (NeighborGraph.pathLinks). They never enter g.edges, so the affinity
// scoring, hop resolution, bridge/redundancy scores and the neighbor-graph
// endpoint are unchanged. The only consumer is GET /api/analytics/path-links
// and the map overlay that draws them.
//
// A hop is resolved for this purpose only when it can be pinned down without
// guessing:
//
//  1. unique: the prefix (after the path-trust threshold, #1784) maps to
//     exactly one relay-capable node; or
//  2. geo: the prefix is ambiguous, but exactly one candidate with GPS lies
//     within pathLinkMaxHopKm of every located, already-resolved neighbour of
//     that hop (the previous / next hop, or the originator and the observer
//     at the two ends of the path). At least one located neighbour is
//     required.
//
// A node appears at most once in a flood path (firmware Mesh.cpp:
// wasSeen/markSeen), so a pubkey resolved at two positions shows the prefix
// is shared with a node we do not know; both positions are dropped.
//
// A link is recorded when both ends resolve, they differ, and, when both are
// located, they are at most pathLinkMaxHopKm apart. A transmission counts once
// per link however many observers heard it; the observers are kept as
// corroboration.

import (
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/meshcore-analyzer/packetpath"
)

// pathLinkMaxHopKm bounds a single resolved hop, both for geo disambiguation
// and for accepting a link between two located nodes. 120 km matches the
// "long hop" threshold of the client path model (#2245).
// TODO(customizer, AGENTS rule 8): expose with the other map thresholds.
const pathLinkMaxHopKm = 120.0

// pathLinkSaturationCount: transmissions after which a path link's count
// contributes full weight to its score.
const pathLinkSaturationCount = 20

// PathLink is one undirected hop↔hop link seen in the middle of packet paths.
type PathLink struct {
	NodeA, NodeB string
	Count        int             // distinct transmissions that carried the link
	GeoResolved  int             // of those, how many needed geo disambiguation
	FirstSeen    time.Time       //
	LastSeen     time.Time       //
	Observers    map[string]bool // observers whose observation carried it
	// HashBytes tallies the link by the shorter hop prefix of the pair in
	// bytes (1, 2 or 3; 0 = unknown), like NeighborEdge.CountsByMode.
	HashBytes map[int]int
}

// Score is the time-decayed strength of the link in [0, 1], with the same
// 7-day half-life as NeighborEdge.Score.
func (l *PathLink) Score(now time.Time) float64 {
	countFactor := float64(l.Count) / float64(pathLinkSaturationCount)
	if countFactor > 1 {
		countFactor = 1
	}
	hours := now.Sub(l.LastSeen).Hours()
	if hours < 0 {
		hours = 0
	}
	return countFactor * math.Exp(-affinityLambda*hours)
}

// countAtLeastBytes returns how many transmissions carried the link with
// both prefixes at least minBytes long.
func (l *PathLink) countAtLeastBytes(minBytes int) int {
	if minBytes <= 1 {
		return l.Count
	}
	n := 0
	for b, c := range l.HashBytes {
		if b >= minBytes {
			n += c
		}
	}
	return n
}

// PathLinks returns a snapshot of the graph's path links.
func (g *NeighborGraph) PathLinks() []*PathLink {
	g.mu.RLock()
	defer g.mu.RUnlock()
	out := make([]*PathLink, 0, len(g.pathLinks))
	for _, l := range g.pathLinks {
		out = append(out, l)
	}
	return out
}

// addPathLink records one transmission carrying a↔b. Caller dedupes per
// transmission. hashBytes is the shorter prefix length of the pair.
func (g *NeighborGraph) addPathLink(a, b, observer string, ts time.Time, hashBytes int, viaGeo bool) {
	key := makeEdgeKey(a, b)
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.pathLinks == nil {
		g.pathLinks = make(map[edgeKey]*PathLink)
	}
	l, ok := g.pathLinks[key]
	if !ok {
		l = &PathLink{
			NodeA: key.A, NodeB: key.B,
			FirstSeen: ts, LastSeen: ts,
			Observers: make(map[string]bool),
			HashBytes: make(map[int]int),
		}
		g.pathLinks[key] = l
	}
	l.Count++
	if viaGeo {
		l.GeoResolved++
	}
	switch hashBytes {
	case 1, 2, 3:
	default:
		hashBytes = 0
	}
	l.HashBytes[hashBytes]++
	if observer != "" {
		l.Observers[observer] = true
	}
	if ts.After(l.LastSeen) {
		l.LastSeen = ts
	}
	if ts.Before(l.FirstSeen) {
		l.FirstSeen = ts
	}
}

// pathLinkTx carries the transmission-level context shared by all of
// its observations while path links are built.
type pathLinkTx struct {
	seen map[edgeKey]bool // links already counted for this transmission
}

// recordPathLinks resolves one observation's path and adds its mid-path
// links. origin is the originator's full pubkey when the payload carries one
// (ADVERT / ANON_REQ), else "". txs dedupes links per transmission.
func (g *NeighborGraph) recordPathLinks(path []string, origin, observer string, ts time.Time, pm *prefixMap, geo map[string]nodeGeoInfo, trust *packetpath.TrustConfig, txs *pathLinkTx) {
	if len(path) < 2 || pm == nil {
		return
	}
	pks, viaGeo := resolvePathHopsForLinks(path, origin, observer, pm, geo, trust)
	for i := 0; i+1 < len(pks); i++ {
		a, b := pks[i], pks[i+1]
		if a == "" || b == "" || a == b {
			continue
		}
		ga, oka := geo[a]
		gb, okb := geo[b]
		if oka && okb && ga.HasGPS && gb.HasGPS &&
			haversineKm(ga.Lat, ga.Lon, gb.Lat, gb.Lon) > pathLinkMaxHopKm {
			continue
		}
		key := makeEdgeKey(a, b)
		if txs.seen[key] {
			// Same transmission, another observer: corroboration only.
			g.mu.Lock()
			if l := g.pathLinks[key]; l != nil && observer != "" {
				l.Observers[observer] = true
			}
			g.mu.Unlock()
			continue
		}
		if txs.seen == nil {
			txs.seen = make(map[edgeKey]bool)
		}
		txs.seen[key] = true
		hb := len(path[i]) / 2
		if nb := len(path[i+1]) / 2; nb < hb {
			hb = nb
		}
		g.addPathLink(a, b, observer, ts, hb, viaGeo[i] || viaGeo[i+1])
	}
}

// resolvePathHopsForLinks pins each hop of a path to a pubkey where that is
// possible without guessing (see the file comment). Unresolved positions are
// "". viaGeo marks positions resolved by geo disambiguation. start and end
// are the located context beyond the two ends of the path: the originator
// (may be "") and the observer.
func resolvePathHopsForLinks(path []string, start, end string, pm *prefixMap, geo map[string]nodeGeoInfo, trust *packetpath.TrustConfig) ([]string, []bool) {
	n := len(path)
	pks := make([]string, n)
	viaGeo := make([]bool, n)
	cands := make([][]nodeInfo, n)
	for i, hop := range path {
		if !packetpath.MeetsPathTrust(len(hop)/2, trust) {
			continue
		}
		c := pm.relayCandidates(hop)
		cands[i] = c
		if len(c) == 1 {
			pks[i] = strings.ToLower(c[0].PublicKey)
		}
	}
	dropRepeats(pks, viaGeo)

	located := func(pk string) (nodeGeoInfo, bool) {
		if pk == "" {
			return nodeGeoInfo{}, false
		}
		gi, ok := geo[pk]
		return gi, ok && gi.HasGPS
	}

	// Geo passes: each resolution can anchor its neighbours, so repeat until
	// nothing changes (at most n passes, each O(n × candidates)).
	for pass := 0; pass < n; pass++ {
		changed := false
		for i := 0; i < n; i++ {
			if pks[i] != "" || len(cands[i]) < 2 {
				continue
			}
			left, right := start, end
			if i > 0 {
				left = pks[i-1]
			}
			if i < n-1 {
				right = pks[i+1]
			}
			var anchors []nodeGeoInfo
			if gi, ok := located(left); ok {
				anchors = append(anchors, gi)
			}
			if gi, ok := located(right); ok {
				anchors = append(anchors, gi)
			}
			if len(anchors) == 0 {
				continue
			}
			pick, matches := "", 0
			for _, c := range cands[i] {
				if !c.HasGPS {
					continue
				}
				fits := true
				for _, a := range anchors {
					if haversineKm(a.Lat, a.Lon, c.Lat, c.Lon) > pathLinkMaxHopKm {
						fits = false
						break
					}
				}
				if fits {
					matches++
					pick = strings.ToLower(c.PublicKey)
				}
			}
			if matches == 1 {
				pks[i] = pick
				viaGeo[i] = true
				changed = true
			}
		}
		if !changed {
			break
		}
	}
	dropRepeats(pks, viaGeo)
	return pks, viaGeo
}

// dropRepeats clears every position whose pubkey occurs more than once: a
// node forwards a flood packet once, so a repeat means the prefix belongs to
// a node we do not know.
func dropRepeats(pks []string, viaGeo []bool) {
	count := make(map[string]int, len(pks))
	for _, pk := range pks {
		if pk != "" {
			count[pk]++
		}
	}
	for i, pk := range pks {
		if pk != "" && count[pk] > 1 {
			pks[i] = ""
			viaGeo[i] = false
		}
	}
}

// ─── API ───────────────────────────────────────────────────────────────────────

// PathLinkJSON is one link in the /api/analytics/path-links response.
type PathLinkJSON struct {
	Source      string         `json:"source"`
	Target      string         `json:"target"`
	Count       int            `json:"count"`
	GeoResolved int            `json:"geo_resolved"`
	Observers   int            `json:"observers"`
	Score       float64        `json:"score"`
	FirstSeen   string         `json:"first_seen"`
	LastSeen    string         `json:"last_seen"`
	HashBytes   map[string]int `json:"hash_bytes"`
}

// PathLinksResponse is the /api/analytics/path-links response.
type PathLinksResponse struct {
	Links   []PathLinkJSON `json:"links"`
	Total   int            `json:"total"`
	MaxHops float64        `json:"max_hop_km"`
}

// handlePathLinks serves the mid-path hop↔hop links.
//
// Query: min_count (default 2) — minimum transmissions; min_hash_bytes
// (1-3, default 1) — count only sightings where both prefixes have at least
// that many bytes; limit (default 2000, max 10000), strongest first.
func (s *Server) handlePathLinks(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	minCount := 2
	if v, err := strconv.Atoi(q.Get("min_count")); err == nil && v > 0 {
		minCount = v
	}
	minBytes := 1
	if v, err := strconv.Atoi(q.Get("min_hash_bytes")); err == nil && v >= 1 && v <= 3 {
		minBytes = v
	}
	limit := 2000
	if v, err := strconv.Atoi(q.Get("limit")); err == nil && v > 0 {
		limit = v
	}
	if limit > 10000 {
		limit = 10000
	}
	writeJSON(w, s.cachedPathLinks(minCount, minBytes, limit))
}

// pathLinksCacheTTL: the graph is rebuilt on the recompute tick, and the
// hidden-name filter costs a node lookup per endpoint, so a response is
// reused for a while per query shape.
const pathLinksCacheTTL = 2 * time.Minute

// pathLinksCacheMax bounds the number of cached query shapes.
const pathLinksCacheMax = 32

type pathLinksCacheKey struct{ minCount, minBytes, limit int }

type pathLinksCacheEntry struct {
	at   time.Time
	resp PathLinksResponse
}

type pathLinksCacheField struct {
	mu      sync.Mutex
	entries map[pathLinksCacheKey]pathLinksCacheEntry
}

func (s *Server) cachedPathLinks(minCount, minBytes, limit int) PathLinksResponse {
	key := pathLinksCacheKey{minCount, minBytes, limit}
	c := &s.pathLinksCache
	c.mu.Lock()
	if e, ok := c.entries[key]; ok && time.Since(e.at) < pathLinksCacheTTL {
		c.mu.Unlock()
		return e.resp
	}
	c.mu.Unlock()

	resp := s.computePathLinks(minCount, minBytes, limit)

	c.mu.Lock()
	if c.entries == nil || len(c.entries) >= pathLinksCacheMax {
		c.entries = make(map[pathLinksCacheKey]pathLinksCacheEntry)
	}
	c.entries[key] = pathLinksCacheEntry{at: time.Now(), resp: resp}
	c.mu.Unlock()
	return resp
}

func (s *Server) computePathLinks(minCount, minBytes, limit int) PathLinksResponse {
	resp := PathLinksResponse{Links: []PathLinkJSON{}, MaxHops: pathLinkMaxHopKm}
	if s.store == nil {
		return resp
	}
	now := time.Now()
	links := s.getNeighborGraph().PathLinks()
	out := make([]PathLinkJSON, 0, len(links))
	hidden := make(map[string]bool)
	isHidden := func(pk string) bool {
		h, ok := hidden[pk]
		if !ok {
			h = s.isPubkeyHidden(pk)
			hidden[pk] = h
		}
		return h
	}
	for _, l := range links {
		cnt := l.countAtLeastBytes(minBytes)
		if cnt < minCount {
			continue
		}
		if s.cfg != nil && (s.cfg.IsBlacklisted(l.NodeA) || s.cfg.IsBlacklisted(l.NodeB)) {
			continue
		}
		if isHidden(l.NodeA) || isHidden(l.NodeB) {
			continue
		}
		hb := make(map[string]int, len(l.HashBytes))
		for b, c := range l.HashBytes {
			hb[strconv.Itoa(b)] = c
		}
		out = append(out, PathLinkJSON{
			Source: l.NodeA, Target: l.NodeB,
			Count: cnt, GeoResolved: l.GeoResolved,
			Observers: len(l.Observers),
			Score:     l.Score(now),
			FirstSeen: l.FirstSeen.UTC().Format(time.RFC3339),
			LastSeen:  l.LastSeen.UTC().Format(time.RFC3339),
			HashBytes: hb,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		if out[i].Source != out[j].Source {
			return out[i].Source < out[j].Source
		}
		return out[i].Target < out[j].Target
	})
	resp.Total = len(out)
	if len(out) > limit {
		out = out[:limit]
	}
	resp.Links = out
	return resp
}

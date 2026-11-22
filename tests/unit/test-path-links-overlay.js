/**
 * "Packet-path links" map overlay in public/map.js: relay↔relay links from
 * the middle of packet paths, served by /api/analytics/path-links.
 *
 *  - structural pins for the DOM/Leaflet wiring;
 *  - behavioral tests of the pure core computePathLinkLines.
 */
'use strict';
const REPO_ROOT = require('path').resolve(__dirname, '..', '..');
const fs = require('fs');
const path = require('path');

let passed = 0, failed = 0;
function assert(cond, msg) {
  if (cond) { passed++; console.log('  ✓ ' + msg); }
  else { failed++; console.error('  ✗ ' + msg); }
}

const src = fs.readFileSync(path.join(REPO_ROOT, 'public', 'map.js'), 'utf8');

console.log('\n=== overlay wiring (structural) ===');
assert(/<input type="checkbox" id="mcPathLinks">/.test(src), 'controls template has the #mcPathLinks toggle');
assert(/type="range" id="mcPathLinksMin"/.test(src), 'min-count slider present');
assert(/id="mcPathLinksBytes"/.test(src) && /value="3">3-byte only/.test(src), 'hash-size select present');
assert(/function loadPathLinks[\s\S]{0,400}\/analytics\/path-links/.test(src), 'loadPathLinks fetches /analytics/path-links');
assert(/checked\) loadPathLinks\(\); else clearPathLinks\(\)/.test(src), 'toggle wires loadPathLinks/clearPathLinks');
assert(/pathLinksLayer = L\.layerGroup\(\)/.test(src) && /dashArray: '6 6'/.test(src), 'renders a dedicated dashed layer');
assert(/clearTimeout\(pathLinksRenderTimer\)/.test(src), 'slider redraw is debounced and the timer cleared');

const start = src.indexOf('function computePathLinkLines');
const end = src.indexOf('function clearPathLinks');
if (start < 0 || end < 0) { console.error('  ✗ could not locate computePathLinkLines'); process.exit(1); }
const M = new Function(src.slice(start, end) + '\nreturn { computePathLinkLines };')();

console.log('\n=== computePathLinkLines (behavioral) ===');
const nodes = [
  { public_key: 'AA', lat: 49.2, lon: 7.0 },
  { public_key: 'BB', lat: 49.3, lon: 6.9 },
  { public_key: 'CC', lat: 49.4, lon: 6.6 },
  { public_key: 'DD', lat: null, lon: null }, // no GPS
  { public_key: 'EE', lat: 0, lon: 0 },       // 0,0 = no GPS
];
const links = [
  { source: 'aa', target: 'bb', count: 10 },
  { source: 'bb', target: 'cc', count: 5 },
  { source: 'aa', target: 'cc', count: 1 },
  { source: 'aa', target: 'dd', count: 50 },
  { source: 'bb', target: 'ee', count: 50 },
];
let r = M.computePathLinkLines(links, nodes, 1);
assert(r.length === 3, 'links with an endpoint without GPS (or 0,0) are dropped');
assert(r[0].a === 'aa' && r[0].b === 'bb' && r[0].rel === 1, 'most-seen first, rel = 1');
assert(Math.abs(r[1].rel - 0.5) < 1e-9, 'rel = count / max count');
assert(Array.isArray(r[0].pa) && r[0].pa[0] === 49.2, 'endpoint coordinates attached');
r = M.computePathLinkLines(links, nodes, 5);
assert(r.length === 2 && r.every(t => t.count >= 5), 'minCount filters links');
r = M.computePathLinkLines(links, nodes, 'x');
assert(r.length === 3, 'invalid minCount falls back to 1');
assert(M.computePathLinkLines(null, nodes, 1).length === 0, 'null links → empty');
assert(M.computePathLinkLines([{ source: 'AA', target: 'aa', count: 3 }], nodes, 1).length === 0, 'self-link dropped');

console.log('\n' + passed + ' passed, ' + failed + ' failed');
process.exit(failed ? 1 : 0);

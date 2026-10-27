/* DOM construction only: API strings are always text nodes, including SVG labels. */
export function node(tag, attrs = {}, ...children) {
  const n = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) { if (key.startsWith('on')) n.addEventListener(key.slice(2), value); else if (value !== null && value !== undefined) n.setAttribute(key, String(value)); }
  for (const child of children.flat(4)) if (child !== null && child !== undefined) n.append(child instanceof Node ? child : document.createTextNode(typeof child === 'string' ? child : text(child)));
  return n;
}
const finite = value => typeof value === 'number' && Number.isFinite(value) && value >= 0;
/* The only way an API value becomes display text: strings and finite numbers, never an object's own toString. */
export const text = value => (typeof value === 'string' && value !== '') || (typeof value === 'number' && Number.isFinite(value)) ? String(value) : 'Unavailable';
export function utc(value) { if (typeof value !== 'string' && typeof value !== 'number') return 'Unavailable'; if (value === '') return 'Unavailable'; const d = new Date(typeof value === 'number' ? value * 1000 : value); return Number.isFinite(d.getTime()) ? d.toISOString().replace('T', ' ').replace('.000Z', ' UTC') : 'Unavailable'; }
export function bytes(value) { if (!finite(value)) return 'Unavailable'; const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB']; let n = value; let i = 0; while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; } return `${n < 10 && i ? n.toFixed(1) : Math.round(n)} ${units[i]}`; }
export function secondsAgo(value, now = Date.now()) { if (typeof value !== 'string' || !value) return null; const t = Date.parse(value); const age = (now - t) / 1000; return Number.isFinite(age) && age >= 0 ? age : null; }
export function processingState(c, now = Date.now()) {
  if (!Number.isInteger(c.backlog_batches) || c.backlog_batches < 0 || c.backlog_capped !== false) return {label: 'Unknown', tone: '', age: null};
  if (c.backlog_batches === 0) return c.oldest_pending_received_at === null ? {label: 'Drained', tone: 'good', age: 0} : {label: 'Unknown', tone: '', age: null};
  const age = secondsAgo(c.oldest_pending_received_at, now);
  if (age === null) return {label: 'Unknown', tone: '', age: null};
  return {label: age > 180 ? 'Stalled' : 'Awaiting processing', tone: age > 180 ? 'bad' : '', age};
}
/* 'Current' needs a fresh observation NOW, not at render: both the snapshot and the observation itself age. */
export function liveLabel(current, paused, snapshotAge, observedAge = 0) {
  if (!current) return 'Stale / unknown';
  if (![snapshotAge, observedAge].every(age => Number.isFinite(age) && age >= 0 && age <= 120)) return 'Stale'; // negative = client clock stepped back; NaN/Infinity/null/undefined are never fresh
  return paused ? 'Snapshot (paused)' : 'Current';
}
export function refreshLiveLabels(root, paused, snapshotAge, now = Date.now() / 1000) {
  root.querySelectorAll('[data-live-current]').forEach(el => {
    const observed = Number(el.getAttribute('data-live-observed'));
    const observedAge = el.getAttribute('data-live-observed') === null || el.getAttribute('data-live-observed') === '' || !Number.isFinite(observed) ? null : now - observed;
    el.textContent = liveLabel(el.getAttribute('data-live-current') === 'true', paused, snapshotAge, observedAge);
  });
}
/* observed: epoch seconds of the OLDEST evidence behind the label, kept so freshness is recomputed later. */
const liveValue = (current, observed) => node('span', {'data-live-current': String(current), 'data-live-observed': Number.isFinite(observed) ? String(observed) : ''}, current ? 'Current' : 'Stale / unknown');
export function badge(value, tone = '') { return node('span', {class: `badge ${tone}`}, text(value)); }
const quiet = value => node('span', {class: 'muted'}, value);
export function heading(title, note) { return node('div', {class: 'section-head'}, node('h2', {}, title), note ? node('p', {}, note) : null); }
export function empty(title, description) { return node('div', {class: 'empty'}, node('h2', {}, title), node('p', {}, description)); }
function facts(pairs) { return node('dl', {class: 'facts'}, pairs.flatMap(([key, value]) => [node('dt', {}, key), node('dd', {}, value instanceof Node ? value : text(value))])); }
function table(headers, rows) { return node('div', {class: 'table-wrap', role: 'region', tabindex: '0', 'data-focus-key': `table:${headers.join('|')}`, 'aria-label': `Scrollable table: ${headers.join(', ')}`}, node('table', {class: 'data-table'}, node('thead', {}, node('tr', {}, headers.map(h => node('th', {scope: 'col'}, h)))), node('tbody', {}, rows))); }
export function copyButton(id, scope = 'list') { return node('button', {class: 'copy-button', type: 'button', 'data-focus-key': `copy:${scope}:${id}`, 'aria-label': `Copy identity ID ${id}`, onclick: async event => { try { if (!navigator.clipboard) throw new Error(); await navigator.clipboard.writeText(id); event.target.textContent = 'Copied'; } catch { event.target.textContent = 'Select ID to copy'; } }}, 'Copy ID'); }
function identity(id, name, onSelect) { return node('div', {}, node('button', {class: 'identity-button', type: 'button', 'data-focus-key': `identity:${id}`, onclick: () => onSelect(id)}, node('span', {class: 'identity-name'}, name || 'Unlabelled identity'), node('code', {class: 'identity-id'}, id)), copyButton(id)); }
export function pager(page, count, next, onPage) { return node('div', {class: 'pager'}, node('span', {}, `Page ${page + 1} · ${count} rows shown`), node('div', {}, node('button', {type: 'button', 'data-focus-key': 'pager:previous', disabled: page === 0 ? '' : null, onclick: () => onPage(-1)}, 'Previous'), node('button', {type: 'button', 'data-focus-key': 'pager:next', disabled: !next ? '' : null, onclick: () => onPage(1)}, 'Next'))); }
function validateHours(data) { if (!data || !Array.isArray(data.hours) || data.hours.length > 200 || data.hours.some(h => !h || !Number.isInteger(h.hour) || h.hour < 0 || h.hour % 3600 || !['missing', 'partial', 'eligible', 'open'].includes(h.state) || !Array.isArray(h.reasons) || h.reasons.some(r => typeof r !== 'string'))) throw new Error('Malformed monitoring response'); }
function metric(label, value, note, tone = '') { return node('div', {class: 'metric'}, node('span', {class: 'label'}, label), node('strong', {}, value instanceof Node ? value : text(value)), node('small', {}, note), tone ? badge(tone, tone === 'Current' ? 'good' : 'warn') : null); }
function hourLegend() { return node('div', {class: 'legend'}, ['eligible', 'partial', 'missing', 'open'].map(s => node('span', {}, node('i', {class: `swatch ${s}`, 'aria-hidden': 'true'}), s === 'eligible' ? 'Qualified' : s[0].toUpperCase() + s.slice(1)))); }
const fresh = age => age !== null && age >= 0 && age <= 120;
const UNAVAILABLE = {tone: 'error', text: 'Unavailable · coverage unavailable, so nothing can be concluded'};
const plural = (n, word) => `${n} ${word}${n === 1 ? '' : 's'}`;
/* Every reason the evidence is incomplete or old. Anything missing, capped or unrecognised counts: unknown is never ok. */
function coverageReasons(data, now) {
  const c = data.collector; const age = (value, end) => fresh(secondsAgo(value, now)) && fresh(finite(end) ? now / 1000 - end : null);
  const flawed = h => h.state === 'partial' || h.state === 'missing' || (h.state === 'open' && h.hour + 3600 <= now / 1000);  // an open hour that already ended will never accumulate more
  const gaps = data.hours.filter(flawed).length;
  const gone = Array.isArray(c.monitoring_unavailable) ? c.monitoring_unavailable : null; const backlog = processingState(c, now).label;
  return [
    age(c.latest_observation_received_at, c.latest_window_end) ? null : 'source observation stale or missing',
    age(c.latest_dns_observation_received_at, c.latest_dns_observation_window_end) ? null : 'parsed DNS observation stale or missing',
    gaps ? `${plural(gaps, 'hour')} partial or missing` : null,
    data.hours.some(h => h.state === 'eligible') ? null : 'no qualified hour yet, baseline still accumulating',
    gone === null || c.monitoring_unavailable_capped !== false ? 'evidence incomplete: monitoring scope list missing or capped' : null,
    c.summary_capped === false ? null : 'evidence incomplete: summary capped or unknown',
    backlog === 'Stalled' || backlog === 'Unknown' ? `processing ${backlog.toLowerCase()}` : null,
    gone?.length ? `monitoring unavailable for ${text(gone[0]?.device_id)} · ${text(gone[0]?.reason)}${gone.length > 1 ? ` and ${gone.length - 1} more` : ''}` : null,
  ].filter(Boolean);
}
/* One honest line for the banner above every view; only complete, current evidence with a qualified hour is 'ok'. */
export function coverageStatus(snapshot, now = Date.now()) {
  try {
    if (snapshot?.phase === 'loading') return {tone: 'loading', text: 'Checking · checking coverage'};
    const data = snapshot?.data;
    if (snapshot?.phase !== 'ready' || !data?.collector || typeof data.collector !== 'object') return UNAVAILABLE;
    validateHours(data);
    if (!data.hours.length) return {tone: 'unknown', text: 'Unknown · no coverage data yet'};
    const reasons = coverageReasons(data, now);
    if (reasons.length) return {tone: 'degraded', text: `Warning · ${reasons[0]} (${plural(reasons.length, 'issue')})`};
    const qualified = data.hours.filter(h => h.state === 'eligible').length; const open = data.hours.filter(h => h.state === 'open').length;
    return {tone: 'ok', text: `OK · coverage current; ${plural(qualified, 'qualified hour')}${open ? `, ${open} accumulating` : ''}`};
  } catch { return UNAVAILABLE; }
}
export function coverageView(data) {
  validateHours(data); const c = data.collector; if (!c || typeof c !== 'object') throw new Error('Malformed coverage response');
  if (!data.hours.length) return empty('Coverage unavailable', 'No hourly coverage was returned. There is no basis for a quality conclusion.');
  const currentAge = secondsAgo(c.latest_observation_received_at); const dnsAge = secondsAgo(c.latest_dns_observation_received_at);
  const windowAge = finite(c.latest_window_end) ? Date.now() / 1000 - c.latest_window_end : null;
  const dnsWindowAge = finite(c.latest_dns_observation_window_end) ? Date.now() / 1000 - c.latest_dns_observation_window_end : null;
  const parseTime = value => { const t = typeof value === 'string' && value ? Date.parse(value) : NaN; return Number.isFinite(t) ? t / 1000 : null; };
  const oldest = (received, windowEnd) => { const t = parseTime(received); return t === null || !finite(windowEnd) ? NaN : Math.min(t, windowEnd); };
  const proc = processingState(c); const count = value => Number.isInteger(value) && value >= 0 ? String(value) : 'Unknown';
  const strip = node('div', {class: 'health-strip'}, metric('Observation', liveValue(fresh(currentAge) && fresh(windowAge), oldest(c.latest_observation_received_at, c.latest_window_end)), `Received ${utc(c.latest_observation_received_at)}`), metric('Parsed DNS', liveValue(fresh(dnsAge) && fresh(dnsWindowAge), oldest(c.latest_dns_observation_received_at, c.latest_dns_observation_window_end)), `Received ${utc(c.latest_dns_observation_received_at)}`), metric('Source flags', c.source_flags_latest === 0 ? '0 · None reported' : c.source_flags_latest === null || c.source_flags_latest === undefined ? 'Unknown' : text(c.source_flags_latest), c.source_flags_latest === 8 ? 'Multicast discovery unavailable' : 'Latest observation only; history remains below'), metric('Processing', badge(proc.label, proc.tone), `${count(c.backlog_batches)} pending${c.backlog_capped ? ' (capped)' : ''} · oldest ${proc.age === null ? 'unknown' : `${Math.round(proc.age)}s`}`));
  const counts = Object.fromEntries(['eligible', 'partial', 'missing', 'open'].map(s => [s, data.hours.filter(h => h.state === s).length]));
  const hours = node('div', {class: 'hour-strip', role: 'img', 'aria-label': `Coverage: ${counts.eligible} qualified, ${counts.partial} partial, ${counts.missing} missing, ${counts.open} open hours`}, data.hours.map(h => node('span', {class: `hour ${['eligible', 'partial', 'missing', 'open'].includes(h.state) ? h.state : 'missing'}`, title: `${utc(h.hour)} · ${text(h.state)} · ${(h.reasons || []).join(', ') || 'no reported reasons'}`})));
  const qualityRows = data.hours.filter(h => h.state !== 'eligible').map(h => node('tr', {}, node('td', {}, utc(h.hour)), node('td', {}, badge(h.state, h.state === 'partial' ? 'warn' : '')), node('td', {}, finite(h.qualified_seconds) ? `${h.qualified_seconds}s` : 'Unavailable'), node('td', {}, (h.reasons || []).join(', ') || 'Hour still open')));
  const unavailable = Array.isArray(c.monitoring_unavailable) ? c.monitoring_unavailable : [];
  return node('div', {}, strip, node('section', {class: 'section'}, heading('Coverage over time', `${counts.eligible} qualified · ${counts.partial} partial · ${counts.missing} missing · ${counts.open} open`), hours, hourLegend(), node('p', {class: 'table-note'}, 'A quiet network and missing observations are different states. Open hours are still accumulating evidence.'), node('div', {class: 'chart-meta'}, node('span', {}, data.hours.length ? utc(data.hours[0].hour) : 'No hours'), node('span', {}, data.hours.length ? utc(data.hours.at(-1).hour + 3600) : ''))), node('section', {class: 'section'}, heading('Source record', c.collector_id), facts([['Last batch', `${count(c.last_seq)} · ${utc(c.last_received_at)}`], ['Retained drops', count(c.dropped_batches_in_retained_detail)], ['Detail begins', utc(c.retained_detail_since)], ['Summary', c.summary_capped === false ? 'Retained detail scanned' : 'Capped or unknown · totals may be incomplete'], ['Collector memory', finite(c.agent_rss_kb) ? `${c.agent_rss_kb} KiB` : 'Unavailable'], ['Monitoring', !Array.isArray(c.monitoring_unavailable) ? 'Unknown / list unavailable' : unavailable.length ? `${unavailable.length} scopes unavailable${c.monitoring_unavailable_capped ? ' (capped)' : ''}` : c.monitoring_unavailable_capped === false ? 'No unavailable scopes reported' : 'Unknown / capped']]), unavailable.length ? node('ul', {class: 'plain-list'}, unavailable.map(x => node('li', {}, `${text(x?.device_id)} · ${text(x?.reason)}`))) : null), node('section', {class: 'section'}, heading('Hours that need context', 'Historical quality is separate from current source flags'), qualityRows.length ? table(['Hour · UTC', 'Quality', 'Qualified', 'Reasons'], qualityRows) : empty('All displayed hours qualified', 'This describes the displayed coverage, not device safety or full field-test acceptance.')));
}
export function inventoryView(data, onSelect) {
  if (!Array.isArray(data) || data.length > 25 || data.some(d => !d || typeof d.id !== 'string')) throw new Error('Malformed inventory response');
  if (!data.length) return empty('No identities on this page', 'A bounded scan can return an empty page with more results. Use Next if available.');
  return node('div', {}, node('p', {class: 'mobile-table-hint'}, 'Scroll sideways for type, IP and last seen.'), table(['Inventory identity', 'Type', 'Status', 'Last observed IP', 'Last seen · UTC'], data.map(d => node('tr', {}, node('td', {}, identity(d.id, d.name, onSelect)), node('td', {}, badge(d.type || 'unknown'), node('span', {class: 'subline'}, text(d.type_provenance?.source))), node('td', {}, text(d.status), node('span', {class: 'subline'}, `Identity: ${text(d.identity_state)}`)), node('td', {}, node('code', {class: 'mono'}, d.last_observed_ip || 'Unavailable'), node('span', {class: 'subline'}, utc(d.last_observed_ip_at))), node('td', {}, utc(d.last_seen))))));
}
export function deviceView(d, onActivity) {
  if (!d || typeof d.id !== 'string' || !Array.isArray(d.macs)) throw new Error('Malformed device response');
  const names = [...new Set(d.macs.map(m => m.hostname).filter(h => typeof h === 'string' && h))]; const ch = d.explanation?.characterization;
  return node('aside', {class: 'detail-panel', 'aria-label': 'Identity detail', tabindex: '-1'}, node('span', {class: 'eyebrow'}, 'SELECTED IDENTITY'), node('h2', {}, d.name || 'Unlabelled identity'), node('code', {class: 'identity-id'}, d.id), copyButton(d.id, 'detail'), facts([['Human label', d.name || 'Not assigned'], ['DHCP names', names.join(', ') || 'Not observed'], ['Last observed IP', d.last_observed_ip || 'Unavailable'], ['IP observed at', utc(d.last_observed_ip_at)], ['Type', d.type || 'unknown'], ['Type source', d.type_provenance?.source || 'No supported classification'], ['Identity state', text(d.identity_state)], ['Status', text(d.status)], ['First seen', utc(d.first_seen)], ['Last seen', utc(d.last_seen)], ['Merged into', d.merged_into || 'No active merge']]), node('button', {type: 'button', class: 'primary', 'data-focus-key': `activity:${d.id}`, onclick: () => onActivity(d.id)}, 'View activity'), node('div', {class: 'callout'}, 'IDs identify tracked inventory records. MAC rotation, merges and undo can change the relationship to a physical device. IPs are historical observations.'), ch ? node('section', {}, node('h3', {}, 'Classification evidence'), facts([['Result', ch.inferred_type], ['Strength', ch.strength], ['Reason', ch.reason], ['Model', ch.model_version], ['Valid until', utc(ch.valid_until)]]), node('ul', {class: 'plain-list'}, (ch.evidence || []).map(e => node('li', {}, `${text(e.kind)} · ${text(e.service)} · ${utc(e.observed_at)}`)))) : node('p', {class: 'small muted'}, 'Unknown means the available evidence did not support a current classification.'));
}
function svgNode(tag, attrs = {}, content = null) { const n = document.createElementNS('http://www.w3.org/2000/svg', tag); for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, String(v)); if (content !== null) n.textContent = String(content); return n; }
function activityChart(data) {
  const hours = data.hours; const b = data.baseline; const median = b?.state === 'mature' && finite(b.median_upload_bytes) ? b.median_upload_bytes : null;
  const values = hours.flatMap(h => [h.bytes_up, h.bytes_down]).filter(finite); const max = Math.max(1, ...values, median || 0); const svg = svgNode('svg', {class: 'chart', viewBox: '0 0 920 270', role: 'img', 'aria-label': 'Hourly upload and download. Dashed spaces indicate missing observations. A data table follows.'});
  svg.append(svgNode('title', {}, 'Hourly upload and download · UTC'));
  for (let i = 0; i <= 3; i++) { const y = 215 - i * 58; svg.append(svgNode('line', {x1: 75, x2: 900, y1: y, y2: y, class: 'gridline'}), svgNode('text', {x: 65, y: y + 4, 'text-anchor': 'end'}, bytes(max * i / 3))); }
  const width = 825 / Math.max(hours.length, 1);
  hours.forEach((h, i) => { const x = 75 + i * width; const missing = h.state === 'missing' || (h.reasons || []).includes('raw_missing') || !finite(h.bytes_up) || !finite(h.bytes_down); if (missing) { const gap = svgNode('rect', {x: x + 1, y: 39, width: Math.max(1, width - 2), height: 176, class: 'gap'}); gap.append(svgNode('title', {}, `${utc(h.hour)} · Missing observation`)); svg.append(gap); return; } for (const [key, cls, offset] of [['bytes_up', 'upload', .08], ['bytes_down', 'download', .5]]) { const height = h[key] / max * 174; const bar = svgNode('rect', {x: x + width * offset, y: 215 - height, width: Math.max(1, width * .38), height, class: cls, opacity: h.state === 'eligible' ? 1 : .55}); bar.append(svgNode('title', {}, `${utc(h.hour)} · ${cls} ${bytes(h[key])} · ${h.state}`)); svg.append(bar); } });
  if (median !== null) { const y = 215 - median / max * 174; svg.append(svgNode('line', {x1: 75, x2: 900, y1: y, y2: y, class: 'baseline'}), svgNode('text', {x: 80, y: Math.max(16, y - 7)}, 'Mature upload median')); }
  if (!hours.length) svg.append(svgNode('text', {x: 450, y: 130, 'text-anchor': 'middle'}, 'No hourly observations returned'));
  if (hours.length) svg.append(svgNode('text', {x: 75, y: 247}, utc(hours[0].hour).slice(0, 16)), svgNode('text', {x: 900, y: 247, 'text-anchor': 'end'}, utc(hours.at(-1).hour + 3600).slice(0, 16)));
  return svg;
}
export function activityView(data) {
  validateHours(data); if (!data.baseline || typeof data.device_id !== 'string') throw new Error('Malformed activity response'); const b = data.baseline;
  const states = {learning: 'Learning', mature: 'Mature', rebuilding: 'Rebuilding', rebuilding_quality: 'Rebuilding after quality changes', lineage_unavailable: 'Identity lineage unavailable'};
  const rows = data.hours.map(h => node('tr', {}, node('td', {}, utc(h.hour)), node('td', {}, badge(h.state, h.state === 'partial' ? 'warn' : '')), node('td', {}, bytes(h.bytes_up)), node('td', {}, bytes(h.bytes_down)), node('td', {}, finite(h.dns_queries) ? String(h.dns_queries) : 'Unavailable'), node('td', {}, (h.reasons || []).join(', ') || '—')));
  return node('div', {}, node('div', {class: 'section-head'}, node('h2', {}, 'Traffic over time'), badge(typeof b.state === 'string' && Object.hasOwn(states, b.state) ? states[b.state] : 'Unknown reference state', b.state === 'mature' ? 'good' : '')), node('code', {class: 'identity-id'}, data.device_id), node('div', {class: 'callout'}, b.state === 'mature' ? `Qualified reference available · median upload ${bytes(b.median_upload_bytes)} per hour.` : 'A mature reference is not available for this identity and source. Observed traffic remains visible while the reference learns or rebuilds.'), facts([['Qualified hours', finite(b.sample_hours) ? String(b.sample_hours) : 'Unavailable'], ['Distinct dates', finite(b.distinct_days) ? String(b.distinct_days) : 'Unavailable'], ['Training since', utc(b.training_since)], ['Algorithm', text(b.algorithm)]]), activityChart(data), node('div', {class: 'chart-meta'}, node('span', {}, 'Paired bars · hourly totals'), node('span', {}, 'Partial/open hours are faint · missing hours remain gaps')), node('div', {class: 'legend'}, node('span', {}, node('i', {class: 'swatch upload', 'aria-hidden': 'true'}), 'Upload'), node('span', {}, node('i', {class: 'swatch download', 'aria-hidden': 'true'}), 'Download'), node('span', {}, 'Dashed area: unavailable observations')), node('details', {}, node('summary', {}, 'Hourly observations and quality'), node('div', {class: 'scroll-details'}, table(['Hour · UTC', 'Quality', 'Upload', 'Download', 'DNS', 'Reasons'], rows))), node('p', {class: 'table-note'}, 'Observed totals can be incomplete when coverage is partial. Missing data is never drawn as zero traffic.'));
}
const DETECTORS = new Map([['large_upload', 'Large upload'], ['upload_deviation', 'Upload above reference']]);
const detector = value => typeof value === 'string' && DETECTORS.has(value) ? DETECTORS.get(value) : text(value);
const FILTERS = [['all', 'All'], ['attention', 'Needs attention'], ['quiet', 'Quiet']];
const QUIET_LABELS = new Map([['acknowledged', 'acknowledged'], ['expected', 'expected']]);
/* The decision on record, apart from the verdict: derived = does it need a human; forced = an expired snooze overrides the API flag. */
function decide(r, open, now) {
  if (r === null || r === undefined) return {label: 'no decision', derived: open, forced: false};
  if (typeof r !== 'object' || Array.isArray(r) || typeof r.status !== 'string') return null;
  if (QUIET_LABELS.has(r.status)) return {label: QUIET_LABELS.get(r.status), derived: false, forced: false};
  const until = r.status === 'snoozed' && typeof r.snooze_until === 'string' ? Date.parse(r.snooze_until) : NaN;
  if (!Number.isFinite(until)) return null;
  return now < until ? {label: `snoozed until ${utc(r.snooze_until)}`, derived: false, forced: false} : {label: 'snooze expired', derived: open, forced: open};
}
/* The ONE rule behind both the label and the filter bucket. Unrecognised data fails loud: it needs attention. */
function triage(d, now) {
  const unknown = {label: 'unknown decision', attention: true};
  if (d.attention !== undefined && typeof d.attention !== 'boolean') return unknown;
  const known = d.state === 'open' || d.state === 'resolved' || d.state === 'superseded';  // the API's real set; any other state is one we cannot vouch for
  const decision = decide(d.review, d.state !== 'resolved' && d.state !== 'superseded', now); if (!decision) return unknown;
  const attention = !known || (typeof d.attention === 'boolean' ? d.attention || decision.forced : decision.derived);  // an unrecognised state needs a human whatever the payload says
  const base = attention ? (decision.label === 'no decision' ? 'needs review' : `${decision.label} · needs attention`) : decision.label;
  return {label: known ? base : `${base} · unknown state`, attention};
}
const detectedMs = d => { const t = typeof d.detected_at === 'number' ? d.detected_at * 1000 : typeof d.detected_at === 'string' ? Date.parse(d.detected_at) : NaN; return Number.isFinite(t) ? t : -Infinity; };
function filterBar(active, counts, onFilter) {
  return node('div', {class: 'filter-bar', role: 'group', 'aria-label': 'Filter incidents (changes this view only)'}, FILTERS.map(([name, label]) => node('button', {type: 'button', 'data-focus-key': `filter:${name}`, 'aria-pressed': String(name === active), onclick: () => onFilter(name)}, `${label} (${counts[name]})`)));
}
const activeFilter = filter => FILTERS.some(([name]) => name === filter) ? filter : 'all';
/* Needs-attention first, then newest, ties in API order; works on copies and never writes a decision. */
function triaged(data, now) { return data.map(d => ({d, ...triage(d, now)})).sort((a, b) => Number(b.attention) - Number(a.attention) || detectedMs(b.d) - detectedMs(a.d)); }
export function inboxRows(data, filter, now = Date.now()) { const active = activeFilter(filter); return triaged(data, now).filter(r => active === 'all' || (active === 'attention') === r.attention); }
export function incidentsView(data, onSelect, {filter = 'all', onFilter = () => {}, now = Date.now()} = {}) {
  if (!Array.isArray(data) || data.length > 25 || data.some(d => !d || typeof d.id !== 'string')) throw new Error('Malformed incidents response');  // the API page limit is 25: more is a broken contract, never truncated quietly
  if (!data.length) return empty('No incidents recorded for this scope', 'Absence of incidents is not proof of health: this does not establish healthy coverage or normal device behavior. Check the coverage banner and the Overview.');
  const rows = triaged(data, now); const active = activeFilter(filter); const shown = inboxRows(data, active, now);
  const counts = {all: rows.length, attention: rows.filter(r => r.attention).length, quiet: rows.filter(r => !r.attention).length};
  const bar = filterBar(active, counts, onFilter);
  if (!shown.length) return node('div', {}, bar, empty('No incidents match this filter', `${rows.length} incidents on this page are hidden by the filter. Choose All to see them.`));
  const note = shown.length < rows.length ? node('p', {class: 'table-note'}, `Showing ${shown.length} of ${rows.length} incidents on this page`) : null;
  const row = ({d, label, attention}) => node('tr', {}, node('td', {}, node('button', {class: 'identity-button', type: 'button', 'data-focus-key': `incident:${d.id}`, onclick: () => onSelect(d.id)}, node('span', {class: 'identity-name'}, detector(d.detector)), node('code', {class: 'identity-id'}, d.id))), node('td', {}, node('code', {class: 'mono'}, text(d.device_id)), node('span', {class: 'subline'}, d.current_lineage === true ? 'Current identity lineage' : 'Historical identity lineage')), node('td', {}, badge(d.state, d.state === 'open' ? 'warn' : '')), node('td', {}, badge(label, attention ? 'warn' : '')), node('td', {}, `${bytes(d.observed_bytes)} / ${bytes(d.threshold_bytes)}`), node('td', {}, utc(d.detected_at)));
  return node('div', {}, bar, note, table(['Observation', 'Inventory identity', 'State', 'Decision', 'Observed / threshold', 'Detected · UTC'], shown.map(row)));
}
export function incidentView(d, onActivity) {
  if (!d || !d.evidence || typeof d.id !== 'string') throw new Error('Malformed incident response'); const e = d.evidence;
  return node('aside', {class: 'detail-panel', 'aria-label': 'Incident evidence', tabindex: '-1'}, node('span', {class: 'eyebrow'}, 'EVIDENCE RECORD'), node('h2', {}, detector(d.detector)), badge(d.state, d.state === 'open' ? 'warn' : ''), node('div', {class: 'callout'}, 'Unusual does not mean malicious. This observation is evidence to review, not a safety verdict.'), facts([['Observed upload', bytes(e.observed_bytes)], ['Threshold', bytes(e.threshold_bytes)], ['Observed hour', utc(e.hour)], ['Previous hour', utc(e.previous_hour)], ['Quality required', finite(e.coverage_required_seconds) ? `${e.coverage_required_seconds}s per hour` : 'Unavailable'], ['Reason', text(e.reason_code)], ['Algorithm', text(e.algorithm)], ['Config version', text(e.config_version)], ['Baseline', e.baseline_id || 'No mature baseline'], ['Reference median', e.baseline_id ? bytes(e.baseline_median_upload_bytes) : 'Not used'], ['Qualified hours', finite(e.sample_hours) ? String(e.sample_hours) : 'Unavailable'], ['Distinct dates', finite(e.distinct_days) ? String(e.distinct_days) : 'Unavailable'], ['Current lineage', d.current_lineage ? 'Yes' : 'No · historical evidence']]), node('code', {class: 'identity-id'}, d.device_id), node('button', {type: 'button', 'data-focus-key': `activity:${d.device_id}`, onclick: () => onActivity(d.device_id)}, 'View activity'), node('details', {}, node('summary', {}, 'Provenance identifiers'), facts([['Incident ID', d.id], ['Baseline ID', text(e.baseline_id)], ['Lineage', text(e.lineage)]])));
}

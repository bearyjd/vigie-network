// Offline behaviour contracts for ui/app.js against a minimal fake DOM; no browser, no network, no port.
// Run: node tools/gui/app_contracts.mjs
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';

class FakeNode {}
class FakeText extends FakeNode { constructor(data) { super(); this.data = data; this.parent = null; } }
class FakeElement extends FakeNode {
  constructor(tag) { super(); this.tag = tag; this.attrs = new Map(); this.children = []; this.listeners = {}; this.parent = null; this.hidden = false; this.disabled = false; this.value = ''; }
  setAttribute(key, value) { this.attrs.set(key, String(value)); if (key === 'disabled') this.disabled = true; }
  getAttribute(key) { return this.attrs.has(key) ? this.attrs.get(key) : null; }
  removeAttribute(key) { this.attrs.delete(key); if (key === 'disabled') this.disabled = false; }
  append(...items) { for (const item of items) { item.parent = this; this.children.push(item); } }
  // Like a browser: removing the focused node (or an ancestor) drops focus to <body>.
  replaceChildren(...items) { if (this.contains(document.activeElement) && document.activeElement !== this) document.activeElement = body; for (const old of this.children) old.parent = null; this.children = []; this.append(...items); }
  get localName() { return this.tag; }
  addEventListener(type, listener) { (this.listeners[type] ||= []).push(listener); }
  fire(type, event = {preventDefault() {}}) { for (const listener of this.listeners[type] || []) listener(event); }
  contains(other) { for (let n = other; n; n = n.parent) if (n === this) return true; return false; }
  focus() { if (!this.disabled) document.activeElement = this; }
  scrollIntoView() {}
  get textContent() { return this.children.map(c => (c instanceof FakeText ? c.data : c.textContent)).join(''); }
  set textContent(value) { for (const old of this.children) old.parent = null; this.children = []; if (value !== '') this.append(new FakeText(String(value))); }
  matches(selector) { if (selector === '*') return true; return selector.startsWith('[') ? this.attrs.has(selector.slice(1, -1)) : this.tag === selector; }
  querySelectorAll(selector) { const found = []; for (const c of this.children) if (c instanceof FakeElement) { if (c.matches(selector)) found.push(c); found.push(...c.querySelectorAll(selector)); } return found; }
  querySelector(selector) { return this.querySelectorAll(selector)[0] ?? null; }
}
const violations = [];  // any write to an HTML-parsing sink, document.write or browser storage is a contract failure
for (const sink of ['innerHTML', 'outerHTML']) Object.defineProperty(FakeElement.prototype, sink, {get() { return ''; }, set(value) { violations.push(`${sink}=${value}`); }});
FakeElement.prototype.insertAdjacentHTML = function insertAdjacentHTML() { violations.push('insertAdjacentHTML'); };
const ids = ['preview-banner', 'connect-collector', 'content', 'notice', 'connect-panel', 'workspace', 'disconnect', 'connection-state', 'view-title', 'scope-label', 'refresh', 'refresh-status', 'token', 'connect-form', 'collector', 'scope-form', 'range', 'coverage-banner'];
const elements = Object.fromEntries(ids.map(id => [id, new FakeElement('div')]));
for (const id of ['content', 'notice']) elements[id].parent = null;
elements.refresh.tag = 'button';
const body = new FakeElement('body');
const navButtons = ['overview', 'inventory', 'activity', 'incidents'].map(view => Object.assign(new FakeElement('button'), {dataset: {view}}));
const documentListeners = {};
globalThis.Node = FakeNode;
globalThis.document = {
  hidden: false, activeElement: body,
  getElementById: id => elements[id], createElement: tag => new FakeElement(tag), createElementNS: (ns, tag) => new FakeElement(tag), createTextNode: data => new FakeText(String(data)),
  write: () => violations.push('document.write'), writeln: () => violations.push('document.writeln'),
  querySelectorAll: selector => selector === 'nav button[data-view]' ? navButtons : [], querySelector: () => null, addEventListener: (type, listener) => { (documentListeners[type] ||= []).push(listener); },
};
let storageTouched = false;  // the inbox filter lives in the URL hash only
const storageTrap = name => ({get() { storageTouched = true; violations.push(name); throw new Error(`${name} is off limits`); }});
for (const name of ['localStorage', 'sessionStorage']) Object.defineProperty(globalThis, name, storageTrap(name));
globalThis.location = {origin: 'http://127.0.0.1:1', search: '', hash: ''};
const windowListeners = {};
globalThis.window = {addEventListener: (type, listener) => { (windowListeners[type] ||= []).push(listener); }};
for (const name of ['localStorage', 'sessionStorage']) Object.defineProperty(globalThis.window, name, storageTrap(name));
const realNow = Date.now; let clock = Date.parse('2026-10-25T12:00:00Z'); Date.now = () => clock;
// Timers are counted, never fired: the suite drives time itself.
let intervalTick = null; let nextTimer = 1; let scheduledTotal = 0; const intervals = new Map(); const liveTimeouts = new Map();
globalThis.setInterval = (callback, ms) => { const id = nextTimer++; intervals.set(id, {callback, ms}); intervalTick = callback; return id; };
globalThis.clearInterval = id => { intervals.delete(id); };
globalThis.setTimeout = (callback, ms) => { const id = nextTimer++; liveTimeouts.set(id, {ms, callback, due: clock + ms}); if (ms >= 30000) scheduledTotal++; return id; };
globalThis.clearTimeout = id => { liveTimeouts.delete(id); };
const dueTimers = () => [...liveTimeouts.entries()].filter(([, timer]) => timer.ms >= 30000);
const refreshTimers = () => dueTimers().length;  // the 15 s request deadlines are shorter
const tick = async ms => { clock += ms; for (const [id, timer] of [...liveTimeouts]) if (timer.due <= clock) { liveTimeouts.delete(id); timer.callback(); } await flush(); };  // fire a timer only when the fake clock reaches it
const flush = async () => { for (let i = 0; i < 8; i++) await new Promise(resolve => setImmediate(resolve)); };

let holdCoverage = null; let lastHourState = 'eligible'; let incidentPages = null; let collectorOver = {}; let incidentsDown = false; let coverageDown = false; let hourState = 'eligible'; let unavailable = []; let incidents = [];  // knobs for the banner and inbox contracts
let mode = 'ok'; let retryAfter = '60'; let windowLag = null; let lag = 0;  // seconds between the observation and the fetch
function coverageBody(url) {
  const from = Number(url.searchParams.get('from_hour')); const to = Number(url.searchParams.get('to_hour'));
  const hours = Array.from({length: (to - from) / 3600}, (_, i) => ({hour: from + i * 3600, state: i === 0 ? hourState : i === (to - from) / 3600 - 1 ? lastHourState : 'eligible', observed_seconds: 3600, qualified_seconds: 3600, reasons: [], bytes_up: 1, bytes_down: 1, flows: 1, dns_queries: 1}));
  const now = clock / 1000; const stamp = new Date(clock - lag * 1000).toISOString();
  const collector = {collector_id: 'c1', latest_observation_received_at: stamp, latest_window_end: now - (windowLag ?? lag), latest_dns_observation_received_at: stamp, latest_dns_observation_window_end: now - (windowLag ?? lag), backlog_batches: 0, backlog_capped: false, oldest_pending_received_at: null, source_flags_latest: 0, last_seq: 1, last_received_at: stamp, dropped_batches_in_retained_detail: 0, retained_detail_since: stamp, summary_capped: false, agent_rss_kb: 1, monitoring_unavailable: unavailable, monitoring_unavailable_capped: false, ...collectorOver};
  return {ok: true, page: {next_cursor: null}, data: {collector, hours}};
}
let gate = null;  // when set, responses wait for it: a slow manual refresh
const requests = [];  // every request the page makes, for the read-only contract
globalThis.fetch = async (url, options) => {
  requests.push({url: String(url), options});
  if (gate) await gate;
  if (new URL(String(url)).pathname === '/coverage' && holdCoverage) { const held = holdCoverage; holdCoverage = null; await held.promise; return new Response('{}', {status: 503}); }  // one slow, soon obsolete coverage response
  const target = new URL(String(url));
  if (mode === '429') return new Response('{}', {status: 429, headers: {'Retry-After': retryAfter}});
  if (mode === '503') return new Response('{}', {status: 503});
  if (target.pathname === '/coverage' && coverageDown) return new Response('{}', {status: 503});
  if (target.pathname === '/devices') return new Response(JSON.stringify({ok: true, page: {next_cursor: null}, data: []}));
  if (target.pathname.startsWith('/incidents/')) return new Response(JSON.stringify({ok: true, page: {next_cursor: null}, data: {id: target.pathname.slice(11), device_id: 'dev-1', detector: 'large_upload', state: 'open', current_lineage: true, evidence: {}}}));
  if (target.pathname === '/incidents' && incidentsDown) return new Response('{}', {status: 503});
  if (target.pathname === '/incidents' && incidentPages) { const at = Number((target.searchParams.get('cursor') || 'c0').slice(1)); return new Response(JSON.stringify({ok: true, page: {next_cursor: at + 25 < incidentPages.length ? `c${at + 25}` : null}, data: incidentPages.slice(at, at + 25)})); }
  if (target.pathname === '/incidents') return new Response(JSON.stringify({ok: true, page: {next_cursor: null}, data: incidents}));
  return new Response(JSON.stringify(coverageBody(target)));
};

await import('../../server/src/vigie_api/ui/app.js');
assert.equal(typeof intervalTick, 'function', 'a recompute timer must be started');
const content = elements.content; const refresh = elements.refresh; const notice = elements.notice;
const labels = () => content.querySelectorAll('[data-live-current]').map(e => e.textContent);
const status = () => elements['refresh-status'].textContent;

elements.token.value = 'synthetic-token'; elements['connect-collector'].value = 'c1';
elements['connect-form'].fire('submit'); await flush();
assert.deepEqual(labels(), ['Current', 'Current'], 'fresh unpaused snapshot should be current');
assert.equal(refresh.getAttribute('aria-disabled'), 'false');
assert.match(status(), /refresh every 30s/);

// M3: focus inside #content pauses refresh; the badge must stop saying Current immediately.
const anchor = content.querySelector('[data-live-current]'); anchor.focus(); content.fire('focusin');
assert.deepEqual(labels(), ['Snapshot (paused)', 'Snapshot (paused)']);
assert.match(status(), /paused while interacting/);
clock += 121000; intervalTick();
assert.deepEqual(labels(), ['Stale', 'Stale'], 'a paused snapshot older than 120 s is stale');
body.focus = () => { document.activeElement = body; }; body.focus(); content.fire('focusout'); await flush();
assert.deepEqual(labels(), ['Stale', 'Stale'], 'age alone keeps the badge stale after focus leaves');

// Snapshot refresh restores Current; hidden tabs and the timer recompute without any render.
mode = 'ok'; refresh.fire('click'); await flush();
assert.deepEqual(labels(), ['Current', 'Current']);
document.hidden = true; intervalTick();
assert.deepEqual(labels(), ['Snapshot (paused)', 'Snapshot (paused)'], 'hidden tab is paused');
document.hidden = false; intervalTick();
assert.deepEqual(labels(), ['Current', 'Current']);
clock += 119000; intervalTick(); assert.deepEqual(labels(), ['Current', 'Current'], '119 s is still current');
clock += 2000; intervalTick(); assert.deepEqual(labels(), ['Stale', 'Stale'], 'recomputed by timer alone');

// M2 / J9: a 100 s old observation is Current at render, but 30 s later (snapshot only 30 s old) it is not.
lag = 100; refresh.fire('click'); await flush();
assert.deepEqual(labels(), ['Current', 'Current'], 'a 100 s old observation is still fresh at render');
const observed = content.querySelectorAll('[data-live-current]').map(e => Number(e.getAttribute('data-live-observed')));
assert.ok(observed.every(t => Math.abs(t - (clock / 1000 - 100)) < 1), 'observation epoch is stored for later recompute');
clock += 19000; intervalTick(); assert.deepEqual(labels(), ['Current', 'Current'], 'observation 119 s old');
clock += 2000; intervalTick();
assert.deepEqual(labels(), ['Stale', 'Stale'], 'observation 121 s old while the snapshot is only 21 s old');
document.hidden = true; intervalTick(); assert.deepEqual(labels(), ['Stale', 'Stale'], 'pausing never revives an aged observation');
document.hidden = false;
// J12: the OLDEST evidence rules; a fresh receipt does not rescue a 100 s old window.
lag = 10; windowLag = 100; refresh.fire('click'); await flush();
assert.deepEqual(labels(), ['Current', 'Current']);
clock += 21000; intervalTick(); assert.deepEqual(labels(), ['Stale', 'Stale'], 'window 121 s old although received 31 s ago');
windowLag = null; lag = 0; refresh.fire('click'); await flush();
// An observation already stale at render never says Current, and the first chrome() keeps it that way.
lag = 200; refresh.fire('click'); await flush();
assert.deepEqual(labels(), ['Stale / unknown', 'Stale / unknown'], 'stale at render is unknown, not Current');
intervalTick(); assert.deepEqual(labels(), ['Stale / unknown', 'Stale / unknown']);
lag = 0; refresh.fire('click'); await flush();
assert.deepEqual(labels(), ['Current', 'Current']);

// L3 / J11: Refresh aria-disabled follows the rate-limit window without any chrome() trigger other than the timer.
mode = '429'; refresh.fire('click'); await flush();
assert.equal(refresh.getAttribute('aria-disabled'), 'true', 'rate limited refresh must be aria-disabled');
const retry = () => notice.querySelector('button');
assert.equal(retry().disabled, true, 'Retry is disabled inside the Retry-After window');
clock += 59000; intervalTick();
assert.equal(refresh.getAttribute('aria-disabled'), 'true'); assert.equal(retry().disabled, true);
clock += 2000; intervalTick();
assert.equal(refresh.getAttribute('aria-disabled'), 'false', 'aria-disabled must clear when the window ends');
assert.equal(retry().disabled, false, 'Retry must enable when the window ends');

// L2: pressing Retry must not drop focus to <body> whatever the outcome.
mode = '503'; retry().focus(); retry().fire('click'); await flush();
assert.equal(document.activeElement.tag, 'button'); assert.equal(document.activeElement.textContent, 'Retry');
assert.ok(notice.contains(document.activeElement), 'focus stays on the rebuilt Retry button');
mode = '429'; retry().focus(); retry().fire('click'); await flush();
assert.equal(retry().disabled, true);
assert.equal(document.activeElement, notice, 'a disabled Retry hands focus to the notice, not <body>');
clock += 61000; intervalTick(); mode = 'ok'; retry().focus(); retry().fire('click'); await flush();
assert.equal(notice.hidden, true);
assert.equal(document.activeElement, elements['view-title'], 'a cleared notice hands focus to the view title');

// CODEX-A: a slow MANUAL refresh that lands while keyboard focus sits on a content control must
// restore focus to the same logical control, or to Refresh when that control is gone.
mode = 'ok';
const region = () => content.querySelector('[aria-label]');  // stands in for any labelled control
assert.ok(region(), 'the overview renders a labelled element');
let release; gate = new Promise(resolve => { release = resolve; });
refresh.focus(); refresh.fire('click'); await flush();   // keyboard user presses Refresh; response is slow
const before = region(); before.focus(); content.fire('focusin');   // ...then tabs into the content
release(); gate = null; await flush();
assert.notEqual(region(), before, 'content was re-rendered');
assert.equal(document.activeElement, region(), 'focus returns to the same logical control');
assert.equal(document.activeElement.getAttribute('aria-label'), before.getAttribute('aria-label'));
const vanishing = new FakeElement('button'); vanishing.append(new FakeText('Gone after refresh')); content.append(vanishing);
gate = new Promise(resolve => { release = resolve; }); refresh.fire('click'); await flush();
vanishing.focus(); content.fire('focusin'); release(); gate = null; await flush();
assert.equal(document.activeElement, refresh, 'a vanished control hands focus to Refresh, never <body>');
body.focus();

// J7: a notice rebuilt while focus is elsewhere in the page must not steal it.
mode = '503';
const keeper = content.querySelector('[data-live-current]'); keeper.focus(); assert.equal(document.activeElement, keeper);
refresh.fire('click'); await flush();
assert.equal(notice.hidden, false, 'the failed refresh shows a notice');
assert.equal(document.activeElement, keeper, 'a notice that did not hold focus never takes it');
mode = 'ok'; refresh.fire('click'); await flush();
assert.equal(document.activeElement, refresh, 'a vanished live label hands focus to Refresh, never <body>');
body.focus();

// C5/C6 / J02 / J06: focus follows a stable data-focus-key, not mutable text or rank.
{
  const control = (key, label, text, extra = {}) => { const el = new FakeElement('button'); if (key) el.setAttribute('data-focus-key', key); if (label) el.setAttribute('aria-label', label); for (const [k, v] of Object.entries(extra)) el.setAttribute(k, v); el.append(new FakeText(text)); return el; };
  let extras = () => [];
  const render = content.replaceChildren.bind(content);
  content.replaceChildren = (...items) => { render(...items); content.append(...extras()); };
  const refreshWith = async next => { extras = next; refresh.fire('click'); await flush(); };
  const focusOf = () => document.activeElement.getAttribute('data-focus-key');
  mode = 'ok';
  // changed text ('Copy ID' -> 'Copied') keeps focus on the same logical control
  await refreshWith(() => [control('copy:a', null, 'Copy ID')]);
  content.querySelector('[data-focus-key]').focus(); content.fire('focusin');
  await refreshWith(() => [control('copy:a', null, 'Copied')]);
  assert.equal(focusOf(), 'copy:a'); assert.equal(document.activeElement.textContent, 'Copied');
  // two same-text controls reordered: the logical SECOND one (key b) is refocused, not the same rank
  await refreshWith(() => [control('identity:a', null, 'Open'), control('identity:b', null, 'Open')]);
  content.querySelectorAll('[data-focus-key]')[1].focus(); content.fire('focusin');
  await refreshWith(() => [control('identity:b', null, 'Open'), control('identity:a', null, 'Open')]);
  assert.equal(focusOf(), 'identity:b', 'reorder must not hand focus to the same-rank control');
  // same text, different aria-label, second focused
  await refreshWith(() => [control('t:1', 'First table', 'Open'), control('t:2', 'Second table', 'Open')]);
  content.querySelectorAll('[data-focus-key]')[1].focus(); content.fire('focusin');
  await refreshWith(() => [control('t:1', 'First table', 'Open'), control('t:2', 'Second table', 'Open')]);
  assert.equal(focusOf(), 't:2');
  // a key whose replacement is DISABLED (Next after the last page) falls back to Refresh
  await refreshWith(() => [control('pager:next', null, 'Next')]);
  content.querySelector('[data-focus-key]').focus(); content.fire('focusin');
  assert.equal(focusOf(), 'pager:next');
  await refreshWith(() => [control('pager:next', null, 'Next', {disabled: ''})]);
  assert.equal(document.activeElement, refresh, 'a disabled replacement hands focus to Refresh');
  // aria-disabled replacement is not focus-restorable either
  await refreshWith(() => [control('pager:next', null, 'Next')]);
  content.querySelector('[data-focus-key]').focus(); content.fire('focusin');
  await refreshWith(() => [control('pager:next', null, 'Next', {'aria-disabled': 'true'})]);
  assert.equal(document.activeElement, refresh);
  // a keyed control that vanished does not land on a same-text control with another key
  await refreshWith(() => [control('identity:x', null, 'Open')]);
  content.querySelector('[data-focus-key]').focus(); content.fire('focusin');
  await refreshWith(() => [control('identity:y', null, 'Open')]);
  assert.equal(document.activeElement, refresh);
  content.replaceChildren = render; extras = () => []; body.focus(); refresh.fire('click'); await flush(); body.focus();
}

// Unit 6: persistent coverage banner (driven by the coverage data, never green from silence or failure).
const views = await import('../../server/src/vigie_api/ui/views.js');
const banner = elements['coverage-banner'];
const written = []; const bannerProto = Object.getOwnPropertyDescriptor(FakeElement.prototype, 'textContent');  // every announcement is a write
Object.defineProperty(banner, 'textContent', {configurable: true, get() { return bannerProto.get.call(this); }, set(value) { written.push(String(value)); bannerProto.set.call(this, value); }});
const bannerText = () => banner.textContent; const tone = () => banner.getAttribute('data-tone');
const reload = async () => { refresh.fire('click'); await flush(); };
mode = 'ok'; lag = 0; windowLag = null; await reload();
assert.match(bannerText(), /^OK/); assert.equal(tone(), 'ok');
elements.collector.value = 'c1'; elements.range.value = '24'; gate = new Promise(resolve => { release = resolve; });
elements['scope-form'].fire('submit'); await flush();
assert.match(bannerText(), /^Checking/); assert.equal(tone(), 'loading'); assert.doesNotMatch(bannerText(), /^OK/);
release(); gate = null; await flush(); assert.equal(tone(), 'ok');
mode = '503'; await reload();
assert.match(bannerText(), /^Unavailable.*coverage unavailable/); assert.equal(tone(), 'error', 'a failed fetch is never green');
mode = 'ok'; lag = 200; await reload();
assert.match(bannerText(), /^Warning.*stale.*\(2 issues\)/); assert.equal(tone(), 'degraded'); lag = 0;
for (const state of ['partial', 'missing']) { hourState = state; await reload(); assert.match(bannerText(), new RegExp(`^Warning.*${state}`)); assert.equal(tone(), 'degraded'); }
hourState = 'eligible'; lastHourState = 'open'; await reload(); assert.equal(tone(), 'ok', 'the current open hour among qualified ones is not degraded'); assert.match(bannerText(), /^OK · coverage current; 23 qualified hours, 1 accumulating$/, 'the OK wording says what was checked'); lastHourState = 'eligible';
hourState = 'open'; await reload(); assert.equal(tone(), 'degraded', 'an open hour that ended long ago is missing evidence, not accumulating'); assert.match(bannerText(), /^Warning/);
hourState = 'partial'; lag = 200; await reload(); assert.match(bannerText(), /\(3 issues\)/); assert.match(bannerText(), /stale/, 'the first reason leads'); hourState = 'eligible'; lag = 0;
unavailable = [{device_id: '<img src=x onerror=alert(1)>', reason: '</script>'}]; await reload();
assert.match(bannerText(), /^Warning/); assert.ok(bannerText().includes('<img src=x onerror=alert(1)>') && bannerText().includes('</script>'), 'API strings render verbatim');
assert.ok(banner.children.every(child => child instanceof FakeText), 'the banner holds text only'); unavailable = [];
await reload(); assert.equal(tone(), 'ok'); clock += 121000; intervalTick();
assert.equal(tone(), 'degraded', 'an ok banner turns degraded when the observation ages'); await reload();
const empty = views.coverageStatus({phase: 'ready', data: {collector: {}, hours: []}}, clock);
assert.equal(empty.tone, 'unknown'); assert.match(empty.text, /^Unknown.*no coverage data yet/); assert.doesNotMatch(empty.text, /OK/);
for (const bad of [undefined, null, {phase: 'ready'}, {phase: 'ready', data: {hours: 3}}, {phase: 'ready', data: {collector: {}, hours: [{hour: 'x'}]}}, {phase: 'mystery'}]) assert.notEqual(views.coverageStatus(bad, clock).tone, 'ok', `garbage ${JSON.stringify(bad)} is never ok`);

// The banner sits above every view: other views fetch the same coverage endpoint.
const view = name => navButtons.find(b => b.dataset.view === name).fire('click');
incidents = []; view('incidents'); await flush(); assert.equal(tone(), 'ok');
hourState = 'partial'; await reload(); assert.equal(tone(), 'degraded', 'the incidents view shows coverage degradation');
coverageDown = true; await reload(); assert.equal(tone(), 'error', 'a coverage failure on another view is not hidden'); assert.equal(notice.hidden, true, 'the incident list itself still rendered');
coverageDown = false; hourState = 'eligible';

// Unit 6: incident inbox.
const inc = (id, over = {}) => Object.freeze({id, device_id: 'dev-1', detector: 'large_upload', state: 'open', detected_at: 1000, observed_bytes: 5, threshold_bytes: 4, current_lineage: true, review: null, attention: true, ...over});
const rowsOf = el => el.querySelectorAll('tr').slice(1);
const idsOf = el => rowsOf(el).map(r => r.querySelector('code').textContent);
const decisions = el => rowsOf(el).map(r => r.querySelectorAll('td')[3].textContent);
const NOW = Date.parse('2026-10-25T12:00:00Z'); const at = delta => new Date(NOW + delta).toISOString();
const opts = (filter = 'all', onFilter = () => {}) => ({filter, onFilter, now: NOW});
const noop = () => {}; const render = (data, o = opts()) => views.incidentsView(data, noop, o);
const mixed = Object.freeze([
  inc('a', {attention: false, state: 'open', review: {status: 'acknowledged'}, detected_at: 500}), inc('b', {detected_at: 100}), inc('c', {detected_at: 300}),
  inc('d', {attention: undefined, detected_at: 200}), inc('e', {attention: undefined, state: 'resolved', detected_at: 400}), inc('f', {attention: 'yes', detected_at: 50}),
  inc('g', {attention: false, review: {status: 'weird'}, detected_at: 600}), inc('h', {detected_at: 300}), inc('i', {detected_at: 300})]);
assert.deepEqual(idsOf(render(mixed)), ['g', 'c', 'h', 'i', 'd', 'b', 'f', 'a', 'e'], 'attention first, newest first, stable ties, garbage fails loud');
assert.deepEqual(mixed.map(d => d.id), ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i'], 'the API payload is never reordered');
assert.deepEqual(idsOf(render(mixed, opts('attention'))), ['g', 'c', 'h', 'i', 'd', 'b', 'f']);
assert.deepEqual(idsOf(render(mixed, opts('quiet'))), ['a', 'e']);
assert.deepEqual(idsOf(render(mixed, opts('bogus'))), idsOf(render(mixed)), 'an unknown filter means all');
const text = el => el.textContent;
const one = (d) => decisions(render([d]))[0];
assert.equal(one(inc('x', {attention: false, review: {status: 'acknowledged'}})), 'acknowledged');
assert.equal(one(inc('x', {attention: false, review: {status: 'expected'}})), 'expected');
assert.equal(one(inc('x', {attention: false, review: {status: 'snoozed', snooze_until: at(3600000)}})), 'snoozed until 2026-10-25 13:00:00 UTC');
assert.equal(one(inc('x', {attention: false, review: {status: 'snoozed', snooze_until: at(1000)}})), 'snoozed until 2026-10-25 12:00:01 UTC', 'still covered one second before');
assert.match(one(inc('x', {attention: false, review: {status: 'snoozed', snooze_until: at(0)}})), /snooze expired.*needs attention/, 'the snooze ends AT snooze_until');
assert.match(one(inc('x', {attention: false, review: {status: 'snoozed', snooze_until: at(-3600000)}})), /snooze expired.*needs attention/);
assert.deepEqual(idsOf(render([inc('q', {attention: false, detected_at: 1, review: {status: 'snoozed', snooze_until: at(-1)}}), inc('r', {attention: false, detected_at: 9, review: {status: 'acknowledged'}})])), ['q', 'r'], 'an expired snooze sorts as needing attention');
assert.equal(one(inc('x')), 'needs review'); assert.equal(one(inc('x', {attention: false, state: 'resolved'})), 'no decision');
for (const review of ['lol', 7, [], {status: 'bogus'}, {}, {status: 'snoozed', snooze_until: 'garbage'}, {status: 'snoozed'}]) assert.equal(one(inc('x', {review, attention: false})), 'unknown decision', `review ${JSON.stringify(review)}`);
assert.equal(one(inc('x', {attention: null})), 'unknown decision', 'null attention is garbage, not quiet');
const old = inc('o', {attention: undefined, review: {status: 'expected'}}); assert.equal(one(old), 'expected'); assert.equal(rowsOf(render([old, inc('p', {attention: undefined, detected_at: 0})])).length, 2);
assert.deepEqual(idsOf(render([old, inc('p', {attention: undefined, detected_at: 0})])), ['p', 'o'], 'older payloads without attention still sort by decision');
// filter buttons: read-only view state
const bar = render(mixed, opts('quiet', name => picked.push(name))); const picked = [];
const filterButtons = bar.querySelectorAll('button').filter(b => (b.getAttribute('data-focus-key') || '').startsWith('filter:'));
assert.deepEqual(filterButtons.map(b => b.getAttribute('aria-pressed')), ['false', 'false', 'true']); assert.match(filterButtons[1].textContent, /Needs attention \(7\)/);
filterButtons[1].fire('click'); assert.deepEqual(picked, ['attention']);
// truncation and empty state
assert.throws(() => render(Array.from({length: 26}, (_, i) => inc(`z${i}`))), /Malformed incidents/, 'the API page limit is 25: more rows is malformed, never silently truncated');
assert.doesNotMatch(text(render(mixed)), /Showing/); assert.match(text(render(mixed, opts('quiet'))), /Showing 2 of 9 incidents on this page/);
assert.deepEqual(views.inboxRows(mixed, 'quiet', NOW).map(r => r.d.id), ['a', 'e'], 'the pager counts the rows the filter leaves');
const none = render([]); assert.match(text(none), /No incidents recorded for this scope/); assert.match(text(none), /absence of incidents is not proof of health/i);
assert.equal(none.querySelectorAll('span').filter(s => /good/.test(s.getAttribute('class') || '')).length, 0, 'an empty inbox shows no success badge');
assert.match(text(render(mixed.slice(0, 1), opts('attention'))), /No incidents match this filter/);
// XSS: hostile strings are inert text; only the expected tags exist
const hostile = render([inc('<img src=x onerror=alert(1)>', {detector: '</script><script>alert(1)</script>', device_id: '<img onerror=alert(2)>', review: {status: '<b onmouseover=x>'}})]);
const tags = new Set(); (function walk(el) { tags.add(el.tag); el.children.forEach(c => c instanceof FakeElement && walk(c)); })(hostile);
assert.deepEqual([...tags].filter(t => !['div', 'table', 'thead', 'tbody', 'tr', 'th', 'td', 'button', 'span', 'code', 'p'].includes(t)), [], 'no element beyond the expected tags');
for (const needle of ['<img src=x onerror=alert(1)>', '</script><script>alert(1)</script>', '<img onerror=alert(2)>']) assert.ok(text(hostile).includes(needle), `verbatim ${needle}`);
// App wiring: hash round trip, no storage.
incidents = mixed.map(d => ({...d})); location.hash = ''; view('incidents'); await flush();
assert.equal(rowsOf(content).length, 9); const pick = name => content.querySelectorAll('button').find(b => b.getAttribute('data-focus-key') === `filter:${name}`);
pick('attention').fire('click'); assert.equal(location.hash, '#filter=attention'); for (const l of windowListeners.hashchange || []) l(); await flush();
assert.equal(rowsOf(content).length, 7, 'the hash drives the filter');
location.hash = '#filter=quiet'; for (const l of windowListeners.hashchange || []) l(); await flush(); assert.deepEqual(idsOf(content), ['a', 'e']);
location.hash = '#filter=<img onerror=1>'; for (const l of windowListeners.hashchange || []) l(); await flush(); assert.equal(rowsOf(content).length, 9, 'a garbage hash means all'); location.hash = '';
assert.equal(storageTouched, false, 'no browser storage');
// --- Fix round 1: robustness, incomplete evidence, honest labels, behavioural read-only. ---
const hashchange = () => { for (const l of windowListeners.hashchange || []) l(); };
// Item 1: only strings and finite numbers are ever rendered; everything else is 'Unavailable'.
for (const v of [{toString: 1}, ['a'], {a: {b: 1}}, null, undefined, '', Symbol('s'), 10n, NaN, Infinity, true, () => 1]) assert.equal(views.text(v), 'Unavailable', `text(${typeof v})`);
assert.equal(views.text('9007199254740993'), '9007199254740993'); assert.equal(views.text(0), '0'); assert.equal(views.text(-3), '-3');
assert.equal(views.node('p', {}, {toString: 1}, Symbol('q'), 5n).textContent, 'UnavailableUnavailableUnavailable', 'node() never stringifies hostile children');
// Item 2: OK needs complete, current evidence; every gap is a Warning.
const oldStamp = seconds => new Date(clock - seconds * 1000).toISOString();
const fixture = (over = {}, hours = [{hour: 0, state: 'eligible', reasons: []}]) => ({phase: 'ready', data: {hours, collector: {collector_id: 'c1', latest_observation_received_at: oldStamp(0), latest_window_end: clock / 1000, latest_dns_observation_received_at: oldStamp(0), latest_dns_observation_window_end: clock / 1000, backlog_batches: 0, backlog_capped: false, oldest_pending_received_at: null, summary_capped: false, monitoring_unavailable: [], monitoring_unavailable_capped: false, ...over}}});
const statusOf = (over, hours) => views.coverageStatus(fixture(over, hours), clock);
assert.equal(statusOf().tone, 'ok', 'control: complete evidence is ok');
const gaps = {
  'observation stale': {latest_observation_received_at: oldStamp(300)}, 'window stale alone': {latest_window_end: clock / 1000 - 300},
  'dns stale': {latest_dns_observation_received_at: oldStamp(300)}, 'dns window stale': {latest_dns_observation_window_end: clock / 1000 - 300},
  'unavailable list missing': {monitoring_unavailable: undefined}, 'unavailable null': {monitoring_unavailable: null}, 'unavailable object': {monitoring_unavailable: {}}, 'unavailable string': {monitoring_unavailable: 'none'},
  'unavailable capped': {monitoring_unavailable_capped: true}, 'unavailable cap unknown': {monitoring_unavailable_capped: undefined},
  'summary capped': {summary_capped: true}, 'summary cap unknown': {summary_capped: undefined}, 'backlog capped': {backlog_capped: true},
  'window in the future': {latest_window_end: clock / 1000 + 3600}, 'observation in the future': {latest_observation_received_at: new Date(clock + 3600000).toISOString()}, 'dns window in the future': {latest_dns_observation_window_end: clock / 1000 + 3600},
  'backlog stalled': {backlog_batches: 3, oldest_pending_received_at: oldStamp(400)}, 'backlog unknown': {backlog_batches: -1},
};
for (const [name, over] of Object.entries(gaps)) { const result = statusOf(over); assert.equal(result.tone, 'degraded', name); assert.match(result.text, /^Warning/, name); }
assert.equal(statusOf({backlog_batches: 2, oldest_pending_received_at: oldStamp(60)}).tone, 'ok', 'a fresh pending batch is normal flow, not a gap');
const thisHour = Math.floor(clock / 3600000) * 3600; const hour = (offset, state) => ({hour: thisHour + offset * 3600, state, reasons: []});
const allOpen = statusOf({}, [hour(0, 'open')]);
assert.equal(allOpen.tone, 'degraded'); assert.match(allOpen.text, /baseline still accumulating/);
assert.equal(statusOf({}, [hour(-1, 'eligible'), hour(0, 'open')]).tone, 'ok'); assert.equal(statusOf({}, [hour(-3, 'eligible'), hour(-2, 'open'), hour(-1, 'eligible')]).tone, 'degraded', 'an overdue open hour in the middle is a gap');
assert.match(statusOf({}, [hour(-1, 'eligible'), hour(0, 'open')]).text, /^OK · coverage current; 1 qualified hour, 1 accumulating$/);
// Item 1 through the app: hostile coverage never breaks scheduling and never reads ok when incomplete.
const UNAVAIL = 'Unavailable · Unavailable';
const hostileCoverage = [  // [override, banner must warn, text the Overview must still show]
  [{monitoring_unavailable: [{device_id: {toString: 1}, reason: {toString: 1}}]}, true, UNAVAIL], [{monitoring_unavailable: [{device_id: ['a', {b: {c: 1}}], reason: null}]}, true, UNAVAIL], [{monitoring_unavailable: [null]}, true, UNAVAIL],
  [{monitoring_unavailable: [7, 'x', [], {device_id: 'good-dev', reason: 'r1'}]}, true, 'good-dev · r1'],
  [{monitoring_unavailable: 'text'}, true, 'Unknown / list unavailable'], [{monitoring_unavailable: {}}, true, 'Unknown / list unavailable'], [{monitoring_unavailable: null}, true, 'Unknown / list unavailable'], [{monitoring_unavailable: 5}, true, 'Unknown / list unavailable'],
  [{latest_observation_received_at: {toString: 1}}, true, 'Received Unavailable'], [{latest_dns_observation_received_at: {toString: 1}}, true, 'Received Unavailable'], [{latest_window_end: {toString: 1}}, true, 'Stale / unknown'], [{latest_dns_observation_window_end: [1]}, true, 'Stale / unknown'],
  [{backlog_batches: '9007199254740993'}, true, 'Unknown pending'], [{summary_capped: {toString: 1}}, true, 'Capped or unknown'],
  [{source_flags_latest: {toString: 1}}, false, 'Unavailable'], [{collector_id: {toString: 1}}, false, 'Source record'], [{last_seq: [1]}, false, 'Unknown ·'], [{last_received_at: {toString: 1}}, false, 'Unavailable'], [{agent_rss_kb: {toString: 1}}, false, 'Unavailable'],
];
mode = 'ok'; lag = 0; windowLag = null; view('overview'); await flush();
for (const base of ['partial', 'healthy']) {  // 'healthy' = every hour qualified, so only the hostile field can make the banner warn
  hourState = base === 'partial' ? 'partial' : 'eligible';
  for (const [over, mustWarn, expected] of hostileCoverage) {
    collectorOver = over; const before = scheduledTotal; await reload(); const where = `${base} base, ${JSON.stringify(over)}`;
    assert.ok(scheduledTotal > before, `refresh keeps rescheduling after ${where}`);
    for (const part of ['Observation', 'Parsed DNS', 'Coverage over time', 'Source record', 'Hours that need context']) assert.ok(content.textContent.includes(part), `Overview still renders "${part}" for ${where}`);
    if (base === 'partial') assert.ok(content.textContent.includes('partial'), `partial hour listed for ${where}`);
    assert.ok(content.textContent.includes(expected), `Overview shows "${expected}" for ${where}`); assert.doesNotMatch(content.textContent, /Data unavailable/);
    assert.ok(['ok', 'degraded'].includes(tone()), 'usable evidence still yields a real banner state, not an error');
    if (base === 'healthy') assert.equal(tone(), mustWarn ? 'degraded' : 'ok', `healthy base: hostile field alone decides the banner for ${where}`);
    else if (mustWarn) assert.equal(tone(), 'degraded', `never ok for ${where}`);
  }
}
hourState = 'eligible';
collectorOver = {}; await reload(); assert.equal(tone(), 'ok');
// Hostile incident fields render as text and never blank the inbox or stop refresh.
const hostileValue = [{toString: 1}, ['x'], {a: {b: 1}}, null, 7, '9007199254740993'];
for (const field of ['state', 'detected_at', 'detector', 'device_id', 'observed_bytes', 'threshold_bytes', 'current_lineage']) for (const value of hostileValue) {
  const rendered = render([inc('h1', {[field]: value}), inc('h2')]); assert.equal(rowsOf(rendered).length, 2, `${field}=${JSON.stringify(value)} keeps the inbox`);
}
incidents = [{...inc('h1'), state: {toString: 1}, detected_at: {toString: 1}, detector: {toString: 1}, review: {status: {toString: 1}}}, {...inc('h2'), attention: {toString: 1}}];
const beforeHostile = scheduledTotal; view('incidents'); await flush(); assert.equal(rowsOf(content).length, 2, 'the inbox is not blank'); assert.ok(scheduledTotal > beforeHostile); assert.equal(tone(), 'ok');
// Item 1b/1c: a throwing refresh status or banner paint never stops rescheduling; the 5 s recompute fails loud.
{
  const rejections = []; const onRejection = error => rejections.push(error); process.on('unhandledRejection', onRejection);
  const statusEl = elements['refresh-status']; const proto = Object.getOwnPropertyDescriptor(FakeElement.prototype, 'textContent'); let calls = 0;
  Object.defineProperty(statusEl, 'textContent', {configurable: true, get() { return proto.get.call(this); }, set(value) { if (++calls === 2) throw new Error('chrome failed'); proto.set.call(this, value); }});
  const before = scheduledTotal; await reload(); await flush();
  assert.ok(scheduledTotal > before, 'schedule() runs even when chrome() throws in the finally'); assert.equal(rejections.length, 1, 'the failure surfaces instead of being swallowed');
  process.off('unhandledRejection', onRejection); delete statusEl.textContent;
  const paint = banner.setAttribute; banner.setAttribute = () => { throw new Error('paint failed'); };
  clock += 121000; intervalTick(); assert.match(bannerText(), /^Unavailable/, 'a failing recompute marks the banner Unavailable'); banner.setAttribute = paint;
  await reload(); assert.equal(tone(), 'ok');
}
// Item 3: the unchanged live region is not rewritten; filter anchors; item 4: no Checking flicker.
written.length = 0; for (let i = 0; i < 3; i++) intervalTick(); assert.equal(written.length, 0, 'an unchanged banner is not re-announced');
for (const name of ['overview', 'inventory', 'activity', 'incidents', 'overview']) { view(name); await flush(); }
incidents = [inc('s1'), inc('s2', {attention: false, review: {status: 'acknowledged'}})]; view('incidents'); await flush(); content.querySelectorAll('button').find(b => b.getAttribute('data-focus-key') === 'incident:s1').fire('click'); await flush();
assert.deepEqual(written, [], 'navigation, selection and paging never reset the banner to Checking once a snapshot exists');
for (const bad of ['#filter=attentionx', 'x#filter=attention', '#filter=quiet&x', '#xfilter=quiet', '#filter=', '#FILTER=quiet']) { location.hash = bad; hashchange(); await flush(); assert.equal(rowsOf(content).length, 2, `${bad} means all`); assert.doesNotMatch(content.textContent, /Showing/); }
incidents = mixed.map(d => ({...d})); location.hash = '#filter=quiet'; hashchange(); await flush();
assert.match(content.textContent, /Page 1 · 2 rows shown/, 'the pager counts the rows rendered, not the rows fetched'); location.hash = '';
// Item 5: a failing main fetch still resolves the banner.
incidentsDown = true; elements['scope-form'].fire('submit'); await flush();
assert.equal(tone(), 'ok', 'coverage is applied although the inbox failed'); assert.equal(notice.hidden, false); incidentsDown = false; await reload();
// Item 6: label and filter bucket come from one rule.
{
  const reviews = [null, undefined, {status: 'acknowledged'}, {status: 'expected'}, {status: 'snoozed', snooze_until: at(1000)}, {status: 'snoozed', snooze_until: at(-1000)}, {status: 'bogus'}, 'x'];
  for (const state of ['open', 'resolved', 'superseded', 'bogus', undefined]) for (const review of reviews) for (const attention of [true, false, undefined, 'yes']) {
    const d = inc('p', {state, review, attention}); const label = one(d); const inAttention = idsOf(render([d], opts('attention'))).length === 1; const inQuiet = idsOf(render([d], opts('quiet'))).length === 1;
    assert.equal(inAttention, /needs|unknown decision/.test(label), `${state} ${JSON.stringify(review)} ${attention}: "${label}" must match its bucket`); assert.equal(inQuiet, !inAttention);
  }
  assert.equal(one(inc('x', {state: 'resolved', attention: false, review: {status: 'snoozed', snooze_until: at(-1000)}})), 'snooze expired');
  assert.match(one(inc('x', {attention: false, review: {status: 'snoozed', snooze_until: at(-1000)}})), /^snooze expired · needs attention$/);
  assert.equal(one(inc('x', {attention: true, review: {status: 'snoozed', snooze_until: at(3600000)}})), 'snoozed until 2026-10-25 13:00:00 UTC · needs attention');
  assert.equal(one(inc('x', {attention: true, review: {status: 'acknowledged'}})), 'acknowledged · needs attention');
  assert.equal(one(inc('x', {attention: false})), 'no decision', 'the API attention flag wins over the state');
}
// Round 2: only the known closed states are quiet; any other state needs a human.
for (const state of ['bogus', {toString: 1}, undefined, null, 5, 'OPEN', '']) {
  const d = inc('u1', {state, attention: undefined}); assert.equal(one(d), 'needs review · unknown state', `state ${JSON.stringify(state)} fails loud`);
  assert.deepEqual(idsOf(render([d], opts('attention'))), ['u1']); assert.deepEqual(idsOf(render([d], opts('quiet'))), []);
  for (const attention of [false, true]) { const e = inc('u1', {state, attention}); assert.equal(one(e), 'needs review · unknown state', `attention:${attention} cannot make state ${JSON.stringify(state)} quiet`); assert.deepEqual(idsOf(render([e], opts('quiet'))), []); assert.deepEqual(idsOf(render([e], opts('attention'))), ['u1']); }
  assert.match(one(inc('u1', {state, attention: null})), /unknown/); assert.deepEqual(idsOf(render([inc('u1', {state, attention: null})], opts('attention'))), ['u1']);
  assert.equal(one(inc('u1', {state, attention: false, review: {status: 'acknowledged'}})), 'acknowledged · needs attention · unknown state', 'a decision on an unrecognised state does not quiet it');
  assert.deepEqual(idsOf(render([inc('k1', {state: 'resolved', attention: undefined}), d])), ['u1', 'k1'], 'unknown state sorts ahead of closed ones');
}
for (const state of ['resolved', 'superseded']) assert.equal(one(inc('u1', {state, attention: undefined})), 'no decision', `${state} is closed`);
assert.equal(one(inc('u1', {state: 'open', attention: false, review: {status: 'acknowledged'}})), 'acknowledged', 'a known state keeps the documented quiet rules');
// Item 7: lookup tables never leak prototype members.
assert.doesNotThrow(() => views.deviceView({id: 'd1', macs: [{hostname: {toString: 1}}, {hostname: 'ok'}]}, noop)); assert.match(views.activityView({device_id: 'd1', hours: [], baseline: {state: 'constructor'}}).textContent, /Unknown reference state/);
for (const word of ['constructor', '__proto__', 'toString', 'hasOwnProperty', 'valueOf']) { const row = render([inc('k1', {detector: word, review: {status: word}})]); assert.ok(rowsOf(row)[0].querySelectorAll('td')[0].textContent.startsWith(word), `${word} renders verbatim`); assert.equal(one(inc('k1', {review: {status: word}})), 'unknown decision'); }
// Round 2: real paging with a filter active, and the scheduled callbacks actually run.
{
  incidentPages = Array.from({length: 50}, (_, i) => inc(`i${String(i).padStart(2, '0')}`, i % 5 === 0 ? {attention: false, review: {status: 'acknowledged'}, detected_at: i} : {detected_at: i}));
  const cursors = () => requests.filter(r => new URL(r.url).pathname === '/incidents').map(r => new URL(r.url).searchParams.get('cursor'));
  const press = async key => { content.querySelectorAll('button').find(b => b.getAttribute('data-focus-key') === key).fire('click'); await flush(); };
  const seen = {};
  for (const filter of ['all', 'attention', 'quiet']) {
    location.hash = `#filter=${filter}`; view('incidents'); await flush(); const first = idsOf(content); await press('pager:next'); const second = idsOf(content); const sent = cursors();
    assert.equal(sent.at(-1), 'c25', `Next sends the API cursor (${filter})`); assert.equal(new Set([...first, ...second]).size, first.length + second.length, `no row repeated across pages (${filter})`);
    if (filter === 'all') { assert.equal(first.length, 25); assert.equal(second.length, 25); assert.match(content.textContent, /Page 2 · 25 rows shown/); }
    assert.ok(first.every(id => id < 'i25') && second.every(id => id >= 'i25'), 'each page shows only its own rows'); seen[filter] = [...first, ...second];
    await press('pager:previous'); assert.deepEqual(idsOf(content), first, 'Previous returns the same first page'); assert.equal(cursors().at(-1), null, 'the first page is requested without a cursor');
  }
  assert.deepEqual([...seen.attention, ...seen.quiet].sort(), seen.all.slice().sort(), 'attention plus quiet cover every row exactly once'); assert.equal(seen.quiet.length, 10);
  incidentPages = null; location.hash = '';
  body.focus(); await reload(); assert.equal(dueTimers().length, 1); assert.equal(dueTimers()[0][1].ms, 30000, 'the documented refresh interval is 30 s'); assert.deepEqual([...intervals.values()].map(i => i.ms), [5000], 'one 5 s banner recompute');
  const seenBefore = requests.length; await tick(29999); assert.equal(requests.length, seenBefore, 'nothing fires before the interval elapses'); assert.equal(refreshTimers(), 1);
  await tick(1); assert.ok(requests.length > seenBefore, 'the scheduled refresh really ran at 30 s'); assert.equal(refreshTimers(), 1, 'and re-armed exactly one timer'); assert.equal(dueTimers()[0][1].ms, 30000);
  // while the user holds focus in the content, the due refresh re-arms quietly: no request, same node, same text
  await reload(); body.focus(); const probe = content.querySelector('[data-focus-key]') || content.querySelector('[aria-label]'); probe.focus(); content.fire('focusin');
  const firstChild = content.children[0]; const probeText = probe.textContent; const quietBefore = requests.length;
  await tick(30000); assert.equal(requests.length, quietBefore, 'no request while interacting'); assert.equal(document.activeElement, probe); assert.equal(content.children[0], firstChild); assert.equal(probe.textContent, probeText);
  assert.equal(refreshTimers(), 1, 'exactly one timer re-armed'); assert.equal(dueTimers()[0][1].ms, 30000); body.focus(); content.fire('focusout'); await flush();
}
// Round 3: an obsolete coverage response must not overwrite a fresher banner.
{
  collectorOver = {}; hourState = 'eligible'; lastHourState = 'eligible'; location.hash = ''; view('overview'); await flush(); await reload(); assert.equal(tone(), 'ok');
  let releaseStale; holdCoverage = {promise: new Promise(resolve => { releaseStale = resolve; })};
  view('inventory'); await flush();  // its coverage request is held
  view('overview'); await flush(); assert.equal(tone(), 'ok', 'the fresh overview owns the banner');
  releaseStale(); await flush(); intervalTick(); assert.equal(tone(), 'ok', 'the obsolete response must not flip the banner'); assert.match(bannerText(), /^OK/);
}
// Round 4: an automatic refresh that is still waiting on coverage must not replace content the user has since started using.
{
  incidents = [inc('r1'), inc('r2')]; location.hash = ''; view('incidents'); await flush(); await reload(); assert.equal(tone(), 'ok'); body.focus();
  const startAutomatic = async hold => { await tick(30000); return hold; };
  let releaseCoverage; holdCoverage = {promise: new Promise(resolve => { releaseCoverage = resolve; })};
  await startAutomatic(); await flush();  // the list answered, coverage is still pending
  const probe = content.querySelectorAll('button').find(b => b.getAttribute('data-focus-key') === 'filter:all'); probe.focus(); content.fire('focusin');
  const firstChild = content.children[0]; const probeText = probe.textContent; const contentText = content.textContent; const sent = requests.length;
  releaseCoverage(); await flush();
  assert.equal(content.children[0], firstChild, 'the original content node survives'); assert.equal(content.textContent, contentText); assert.equal(document.activeElement, probe); assert.equal(probe.textContent, probeText);
  assert.equal(tone(), 'error', 'the banner still takes the late coverage result'); assert.equal(requests.length, sent, 'no extra request'); assert.equal(refreshTimers(), 1, 'exactly one refresh timer'); assert.equal(dueTimers()[0][1].ms, 30000);
  // the same holds when the list request itself fails after the user focused a control
  body.focus(); await reload(); body.focus(); gate = new Promise(resolve => { release = resolve; }); incidentsDown = true; await tick(30000);
  const probe2 = content.querySelectorAll('button').find(b => b.getAttribute('data-focus-key') === 'filter:all'); probe2.focus(); content.fire('focusin'); const child2 = content.children[0];
  release(); gate = null; await flush();
  assert.equal(content.children[0], child2, 'a failed automatic refresh leaves the focused content alone'); assert.equal(document.activeElement, probe2); assert.equal(notice.hidden, false); assert.equal(refreshTimers(), 1);
  incidentsDown = false; body.focus(); content.fire('focusout'); await reload();
}
// L2: schedule() called while a timer is still registered (the interacting branch re-arms without load()'s own clear) leaves ONE live timer.
{
  await reload(); const [[, timer]] = dueTimers(); body.focus(); const probe = content.querySelector('[data-focus-key]') || content.querySelector('[aria-label]'); probe.focus(); content.fire('focusin');
  clock += 31000; timer.callback(); await flush();  // the fired timer is deliberately left registered, as a leaked one would be
  assert.equal(refreshTimers(), 1, 'a re-armed refresh replaces the previous timer instead of adding one'); body.focus(); content.fire('focusout'); await flush();
}
// L4: nested API values never reach a recursive flatten; the page still renders.
{
  let deep = 'x'; for (let i = 0; i < 200000; i++) deep = [deep];
  const row = render([inc('d1', {device_id: deep}), inc('d2')]); assert.equal(rowsOf(row).length, 2); assert.ok(rowsOf(row).some(r => r.textContent.includes('Unavailable')));
  assert.doesNotMatch(render([inc('d3', {device_id: ['array-id']})]).textContent, /array-id/, 'only string device ids are shown');
  const collector = {collector_id: 'c1', latest_observation_received_at: oldStamp(0), latest_window_end: clock / 1000, latest_dns_observation_received_at: oldStamp(0), latest_dns_observation_window_end: clock / 1000, backlog_batches: 0, backlog_capped: false, oldest_pending_received_at: null, summary_capped: false, monitoring_unavailable: [{device_id: deep, reason: deep}], monitoring_unavailable_capped: false};
  const hours = [{hour: thisHour, state: 'eligible', reasons: []}]; const overview = views.coverageView({collector, hours});
  assert.ok(overview.textContent.includes('Unavailable · Unavailable')); assert.equal(views.coverageStatus({phase: 'ready', data: {collector, hours}}, clock).tone, 'degraded');
  assert.equal(views.node('p', {}, deep).textContent, 'Unavailable', 'a deeply nested child is text, not a recursion');
}
// Behavioural read-only (addendum B), sinks (C) and timers (D).
await reload(); const doubleCheck = refreshTimers();
for (const name of ['overview', 'inventory', 'activity', 'incidents', 'overview', 'incidents']) { view(name); await flush(); hashchange(); }
await flush();
assert.equal(doubleCheck, 1); assert.equal(refreshTimers(), 1, 'exactly one refresh timer after many view changes'); assert.equal(intervals.size, 1, 'exactly one banner interval');
assert.equal((windowListeners.hashchange || []).length, 1, 'exactly one hashchange listener'); assert.equal((documentListeners.visibilitychange || []).length, 1); assert.equal((windowListeners.pagehide || []).length, 1);
elements.disconnect.fire('click'); assert.equal(refreshTimers(), 0, 'disconnect leaves no refresh timer behind');
assert.ok(requests.length > 25, 'the suite drove real traffic');
for (const {url, options} of requests) { assert.ok([undefined, 'GET'].includes(options?.method), `${url} uses ${options?.method}`); assert.equal(options?.body, undefined, `${url} sends no body`); assert.ok(/^\/(coverage|incidents(\/[^/]+)?|devices)$/.test(new URL(url).pathname), `unexpected endpoint ${url}`); }
assert.deepEqual(violations, [], 'no HTML sink, document.write or storage access happened'); assert.equal(storageTouched, false);
// Static guard on the shipped sources: a cheap tripwire (quote-agnostic), NOT a guarantee; the behavioural checks above are the contract.
const source = name => readFileSync(new URL(`../../server/src/vigie_api/ui/${name}`, import.meta.url), 'utf8');
const banned = /innerHTML|outerHTML|insertAdjacentHTML|\beval\s*\(|\bFunction\s*\(|\bimport\s*\(|document\s*\.\s*write|localStorage|sessionStorage|indexedDB|set(?:Timeout|Interval)\s*\(\s*['"`]/;
const computed = /\b(?:globalThis|window|self|document|this)\s*\[|[\w)\]]\s*\[\s*(?:['"`][^\]\n]*['"`]\s*\+|[^\]\n]*\+\s*['"`]|`)/;
for (const name of ['views.js', 'app.js', 'client.js']) { const code = source(name); assert.doesNotMatch(code, banned, `${name} stays inert`); assert.doesNotMatch(code, computed, `${name} has no computed member access built from strings`); }
for (const name of ['views.js', 'app.js']) assert.doesNotMatch(source(name), /\bfetch\s*\(|XMLHttpRequest|sendBeacon|\bmethod\b/, `${name} never talks to the network itself`);
const clientCode = source('client.js'); assert.deepEqual([...clientCode.matchAll(/\bmethod\s*:\s*(['"`])(\w+)\1/g)].map(m => m[2]), ['GET'], 'the only HTTP verb is GET'); assert.equal((clientCode.match(/\bmethod\b/g) || []).length, 1); assert.doesNotMatch(clientCode, /\bbody\s*:/);
const page = source('index.html'); assert.match(page, /<div id="coverage-banner"[^>]*role="status"[^>]*aria-live="polite"/); assert.doesNotMatch(page, /<form[^>]*method=|<textarea/i);

Date.now = realNow;
console.log('PASS: live Current badge, pause/stale recompute timer, aria-disabled and Retry focus/state contracts; coverage banner states; read-only incident inbox ordering, decisions, filter and inert-text contracts; behavioural read-only, sink and timer contracts.');

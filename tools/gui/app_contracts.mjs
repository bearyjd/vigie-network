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
  getElementById: id => elements[id], createElement: tag => new FakeElement(tag), createTextNode: data => new FakeText(String(data)),
  querySelectorAll: selector => selector === 'nav button[data-view]' ? navButtons : [], querySelector: () => null, addEventListener: (type, listener) => { (documentListeners[type] ||= []).push(listener); },
};
let storageTouched = false;  // the inbox filter lives in the URL hash only
for (const name of ['localStorage', 'sessionStorage']) Object.defineProperty(globalThis, name, {get() { storageTouched = true; throw new Error(`${name} is off limits`); }});
globalThis.location = {origin: 'http://127.0.0.1:1', search: '', hash: ''};
const windowListeners = {};
globalThis.window = {addEventListener: (type, listener) => { (windowListeners[type] ||= []).push(listener); }};
const realNow = Date.now; let clock = Date.parse('2026-10-25T12:00:00Z'); Date.now = () => clock;
let intervalTick = null; globalThis.setInterval = callback => { intervalTick = callback; return 1; };
globalThis.setTimeout = () => 1; globalThis.clearTimeout = () => {};
const flush = async () => { for (let i = 0; i < 8; i++) await new Promise(resolve => setImmediate(resolve)); };

let coverageDown = false; let hourState = 'eligible'; let unavailable = []; let incidents = [];  // knobs for the banner and inbox contracts
let mode = 'ok'; let retryAfter = '60'; let windowLag = null; let lag = 0;  // seconds between the observation and the fetch
function coverageBody(url) {
  const from = Number(url.searchParams.get('from_hour')); const to = Number(url.searchParams.get('to_hour'));
  const hours = Array.from({length: (to - from) / 3600}, (_, i) => ({hour: from + i * 3600, state: i === 0 ? hourState : 'eligible', observed_seconds: 3600, qualified_seconds: 3600, reasons: [], bytes_up: 1, bytes_down: 1, flows: 1, dns_queries: 1}));
  const now = clock / 1000; const stamp = new Date(clock - lag * 1000).toISOString();
  const collector = {collector_id: 'c1', latest_observation_received_at: stamp, latest_window_end: now - (windowLag ?? lag), latest_dns_observation_received_at: stamp, latest_dns_observation_window_end: now - (windowLag ?? lag), backlog_batches: 0, backlog_capped: false, oldest_pending_received_at: null, source_flags_latest: 0, last_seq: 1, last_received_at: stamp, dropped_batches_in_retained_detail: 0, retained_detail_since: stamp, summary_capped: false, agent_rss_kb: 1, monitoring_unavailable: unavailable, monitoring_unavailable_capped: false};
  return {ok: true, page: {next_cursor: null}, data: {collector, hours}};
}
let gate = null;  // when set, responses wait for it: a slow manual refresh
globalThis.fetch = async url => {
  if (gate) await gate;
  const target = new URL(String(url));
  if (mode === '429') return new Response('{}', {status: 429, headers: {'Retry-After': retryAfter}});
  if (mode === '503') return new Response('{}', {status: 503});
  if (target.pathname === '/coverage' && coverageDown) return new Response('{}', {status: 503});
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
assert.match(bannerText(), /^Warning.*stale.*\(1 issue\)/); assert.equal(tone(), 'degraded'); lag = 0;
for (const state of ['partial', 'missing']) { hourState = state; await reload(); assert.match(bannerText(), new RegExp(`^Warning.*${state}`)); assert.equal(tone(), 'degraded'); }
hourState = 'open'; await reload(); assert.equal(tone(), 'ok', 'an open hour is still accumulating, not degraded');
hourState = 'partial'; lag = 200; await reload(); assert.match(bannerText(), /\(2 issues\)/); assert.match(bannerText(), /stale/, 'the first reason leads'); hourState = 'eligible'; lag = 0;
unavailable = [{device_id: '<img src=x onerror=alert(1)>', reason: '</script>'}]; await reload();
assert.match(bannerText(), /^Warning/); assert.ok(bannerText().includes('<img src=x onerror=alert(1)>') && bannerText().includes('</script>'), 'API strings render verbatim');
assert.ok(banner.children.every(child => child instanceof FakeText), 'the banner holds text only'); unavailable = [];
await reload(); assert.equal(tone(), 'ok'); clock += 121000; intervalTick();
assert.equal(tone(), 'degraded', 'an ok banner turns degraded when the observation ages'); await reload();
const empty = views.coverageStatus({phase: 'ready', data: {collector: {}, hours: []}}, clock);
assert.equal(empty.tone, 'unknown'); assert.match(empty.text, /^Unknown.*no coverage data yet/); assert.doesNotMatch(empty.text, /OK/);
for (const bad of [undefined, null, {phase: 'ready'}, {phase: 'ready', data: {hours: 3}}, {phase: 'mystery'}]) assert.notEqual(views.coverageStatus(bad, clock).tone, 'ok', `garbage ${JSON.stringify(bad)} is never ok`);

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
assert.match(one(inc('x', {attention: false, review: {status: 'snoozed', snooze_until: at(0)}})), /snooze expired.*needs review/, 'the snooze ends AT snooze_until');
assert.match(one(inc('x', {attention: false, review: {status: 'snoozed', snooze_until: at(-3600000)}})), /snooze expired.*needs review/);
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
const many = Array.from({length: 30}, (_, i) => inc(`m${i}`, {detected_at: i}));
assert.equal(rowsOf(render(many)).length, 25); assert.match(text(render(many)), /Showing 25 of 30/); assert.deepEqual(idsOf(render(many)).slice(0, 2), ['m29', 'm28']);
assert.doesNotMatch(text(render(many.slice(0, 25))), /Showing/);
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
// Static guard on the shipped sources.
const source = name => readFileSync(new URL(`../../server/src/vigie_api/ui/${name}`, import.meta.url), 'utf8');
for (const name of ['views.js', 'app.js']) { const code = source(name); assert.doesNotMatch(code, /innerHTML|outerHTML|insertAdjacentHTML|\beval\s*\(|new Function|document\.write|localStorage|sessionStorage|indexedDB/, `${name} stays inert`); assert.doesNotMatch(code, /\bfetch\s*\(|XMLHttpRequest|sendBeacon/, `${name} never fetches directly`); }
assert.deepEqual([...source('client.js').matchAll(/method:\s*'(\w+)'/g)].map(m => m[1]), ['GET'], 'the only HTTP verb is GET');
const page = source('index.html'); assert.match(page, /<div id="coverage-banner"[^>]*role="status"[^>]*aria-live="polite"/); assert.doesNotMatch(page, /<form[^>]*method=|<textarea/i);

Date.now = realNow;
console.log('PASS: live Current badge, pause/stale recompute timer, aria-disabled and Retry focus/state contracts; coverage banner states; read-only incident inbox ordering, decisions, filter, truncation and inert-text contracts.');

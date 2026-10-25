// Offline behaviour contracts for ui/app.js against a minimal fake DOM; no browser, no network, no port.
// Run: node tools/gui/app_contracts.mjs
import assert from 'node:assert/strict';

class FakeNode {}
class FakeText extends FakeNode { constructor(data) { super(); this.data = data; this.parent = null; } }
class FakeElement extends FakeNode {
  constructor(tag) { super(); this.tag = tag; this.attrs = new Map(); this.children = []; this.listeners = {}; this.parent = null; this.hidden = false; this.disabled = false; this.value = ''; }
  setAttribute(key, value) { this.attrs.set(key, String(value)); if (key === 'disabled') this.disabled = true; }
  getAttribute(key) { return this.attrs.has(key) ? this.attrs.get(key) : null; }
  removeAttribute(key) { this.attrs.delete(key); if (key === 'disabled') this.disabled = false; }
  append(...items) { for (const item of items) { item.parent = this; this.children.push(item); } }
  replaceChildren(...items) { for (const old of this.children) old.parent = null; this.children = []; this.append(...items); }
  addEventListener(type, listener) { (this.listeners[type] ||= []).push(listener); }
  fire(type, event = {preventDefault() {}}) { for (const listener of this.listeners[type] || []) listener(event); }
  contains(other) { for (let n = other; n; n = n.parent) if (n === this) return true; return false; }
  focus() { if (!this.disabled) document.activeElement = this; }
  scrollIntoView() {}
  get textContent() { return this.children.map(c => (c instanceof FakeText ? c.data : c.textContent)).join(''); }
  set textContent(value) { for (const old of this.children) old.parent = null; this.children = []; if (value !== '') this.append(new FakeText(String(value))); }
  matches(selector) { return selector.startsWith('[') ? this.attrs.has(selector.slice(1, -1)) : this.tag === selector; }
  querySelectorAll(selector) { const found = []; for (const c of this.children) if (c instanceof FakeElement) { if (c.matches(selector)) found.push(c); found.push(...c.querySelectorAll(selector)); } return found; }
  querySelector(selector) { return this.querySelectorAll(selector)[0] ?? null; }
}
const ids = ['preview-banner', 'connect-collector', 'content', 'notice', 'connect-panel', 'workspace', 'disconnect', 'connection-state', 'view-title', 'scope-label', 'refresh', 'refresh-status', 'token', 'connect-form', 'collector', 'scope-form', 'range'];
const elements = Object.fromEntries(ids.map(id => [id, new FakeElement('div')]));
for (const id of ['content', 'notice']) elements[id].parent = null;
elements.refresh.tag = 'button';
const body = new FakeElement('body');
const documentListeners = {};
globalThis.Node = FakeNode;
globalThis.document = {
  hidden: false, activeElement: body,
  getElementById: id => elements[id], createElement: tag => new FakeElement(tag), createTextNode: data => new FakeText(String(data)),
  querySelectorAll: () => [], querySelector: () => null, addEventListener: (type, listener) => { (documentListeners[type] ||= []).push(listener); },
};
globalThis.location = {origin: 'http://127.0.0.1:1', search: ''};
const windowListeners = {};
globalThis.window = {addEventListener: (type, listener) => { (windowListeners[type] ||= []).push(listener); }};
const realNow = Date.now; let clock = Date.parse('2026-10-25T12:00:00Z'); Date.now = () => clock;
let intervalTick = null; globalThis.setInterval = callback => { intervalTick = callback; return 1; };
globalThis.setTimeout = () => 1; globalThis.clearTimeout = () => {};
const flush = async () => { for (let i = 0; i < 8; i++) await new Promise(resolve => setImmediate(resolve)); };

let mode = 'ok'; let retryAfter = '60';
function coverageBody(url) {
  const from = Number(url.searchParams.get('from_hour')); const to = Number(url.searchParams.get('to_hour'));
  const hours = Array.from({length: (to - from) / 3600}, (_, i) => ({hour: from + i * 3600, state: 'eligible', observed_seconds: 3600, qualified_seconds: 3600, reasons: [], bytes_up: 1, bytes_down: 1, flows: 1, dns_queries: 1}));
  const now = clock / 1000; const stamp = new Date(clock - 10000).toISOString();
  const collector = {collector_id: 'c1', latest_observation_received_at: stamp, latest_window_end: now - 10, latest_dns_observation_received_at: stamp, latest_dns_observation_window_end: now - 10, backlog_batches: 0, backlog_capped: false, oldest_pending_received_at: null, source_flags_latest: 0, last_seq: 1, last_received_at: stamp, dropped_batches_in_retained_detail: 0, retained_detail_since: stamp, summary_capped: false, agent_rss_kb: 1, monitoring_unavailable: [], monitoring_unavailable_capped: false};
  return {ok: true, page: {next_cursor: null}, data: {collector, hours}};
}
globalThis.fetch = async url => {
  const target = new URL(String(url));
  if (mode === '429') return new Response('{}', {status: 429, headers: {'Retry-After': retryAfter}});
  if (mode === '503') return new Response('{}', {status: 503});
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

Date.now = realNow;
console.log('PASS: live Current badge, pause/stale recompute timer, aria-disabled and Retry focus/state contracts.');

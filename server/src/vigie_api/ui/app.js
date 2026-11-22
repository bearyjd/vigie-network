import {ApiClient, ApiError, StaleResult, decisionVersion} from './client.js';
import {node, empty, refreshLiveLabels, heading, pager, coverageView, probeStatusView, inventoryView, deviceView, activityView, incidentsView, incidentView, incidentReviewControls, coverageStatus, inboxRows, utc, eventsView, eventFilterForm, timelineSection, EVENT_PAGE, EVENT_MAX_PAGES} from './views.js';

const byId = id => document.getElementById(id);
const client = new ApiClient();
const state = {connected: false, collector: '', hours: 24, view: 'overview', selectedDevice: null, selectedIncident: null, eventFilter: {deviceId: '', kind: ''}, cursors: [null], page: 0, next: null, generation: 0, loading: false, updated: null, coverage: {phase: 'loading'}};
let timer = null;
let pendingReview = null;
let reviewMessage = '';
let reviewSnapshotGeneration = -1;
const titles = {overview: 'Overview', inventory: 'Inventory', activity: 'Activity', incidents: 'Incidents', events: 'Events'};
const preview = new URLSearchParams(location.search).get('preview') === 'synthetic';
byId('preview-banner').hidden = !preview;
if (preview) byId('connect-collector').value = 'synthetic-preview';
const FILTER_HASH = /^#filter=(all|attention|quiet)$/;  // anchored: anything else means 'all'
// The inbox filter is view state only: it lives in the URL hash, never in storage and never in a request.
const inboxFilter = () => FILTER_HASH.exec(location.hash)?.[1] ?? 'all';
function setBanner() {
  const box = byId('coverage-banner'); box.hidden = !state.connected;
  try {
    const status = coverageStatus(state.coverage, Date.now());
    if (box.textContent === status.text && box.getAttribute('data-tone') === status.tone) return;  // an unchanged live region stays quiet
    box.setAttribute('data-tone', status.tone); box.textContent = status.text;
  } catch {  // a banner that cannot be computed or painted must never keep an old, possibly green, state
    box.textContent = 'Unavailable · coverage status could not be computed';
    try { box.setAttribute('data-tone', 'error'); } catch { /* the text above already says it */ }
  }
}
function interacting() {
  const focused = document.activeElement;
  return (state.updated !== null && byId('content').contains(focused)) || byId('overview-probes').contains(focused);
}
// Which control inside #content holds focus. Controls carry a stable data-focus-key (kind + id);
// text and rank are only the fallback for unkeyed controls, so a re-render that changes a label
// ('Copy ID' -> 'Copied') or reorders identical-looking rows still hands focus to the same one.
function focusSignature(el) { return [el.localName, el.getAttribute('aria-label') ?? '', el.textContent].join('\u0000'); }
function focusedInContent() {
  const box = byId('content'); const active = document.activeElement;
  if (active === box || !box.contains(active)) return null;
  const key = active.getAttribute('data-focus-key');
  if (key) return {key};
  const signature = focusSignature(active);
  const same = [...box.querySelectorAll('*')].filter(el => !el.getAttribute('data-focus-key') && focusSignature(el) === signature);
  return {signature, rank: same.indexOf(active)};
}
function focusable(el) { return !el.disabled && el.getAttribute('aria-disabled') !== 'true'; }
function restoreContentFocus(held) {
  if (!held) return;
  const all = [...byId('content').querySelectorAll('*')];
  const match = held.key
    ? all.find(el => el.getAttribute('data-focus-key') === held.key)
    : all.filter(el => !el.getAttribute('data-focus-key') && focusSignature(el) === held.signature)[held.rank];
  if (match && focusable(match)) match.focus({preventScroll: true});
  if (!match || document.activeElement !== match) byId('refresh').focus({preventScroll: true});
}
function resetPage() { state.cursors = [null]; state.page = 0; state.next = null; }
function range() { const to = Math.floor(Date.now() / 3600000) * 3600 + 3600; return {from: to - state.hours * 3600, to}; }
function notice(message = '', retry = false) {
  const box = byId('notice'); const hadFocus = box.contains(document.activeElement); box.replaceChildren(); box.hidden = !message;
  let button = null;
  if (message) { box.append(node('span', {}, message)); if (retry) { button = node('button', {type: 'button', disabled: Date.now() < client.retryAt ? '' : null, onclick: () => load(false)}, 'Retry'); box.append(button); } }
  if (!hadFocus) return;
  if (button && !button.disabled) button.focus({preventScroll: true});
  else if (message) { box.setAttribute('tabindex', '-1'); box.focus({preventScroll: true}); }
  else byId('view-title').focus({preventScroll: true});
}
function chrome() {
  byId('connect-panel').hidden = state.connected; byId('workspace').hidden = !state.connected; byId('disconnect').hidden = !state.connected;
  byId('overview-probes').hidden = !state.connected || state.view !== 'overview';
  byId('connection-state').textContent = state.connected ? (client.writerEnabled ? 'Connected · incident editing' : 'Connected · read-only view') : 'Disconnected';
  document.querySelectorAll('nav button[data-view]').forEach(button => { button.disabled = !state.connected; if (button.dataset.view === state.view && state.connected) button.setAttribute('aria-current', 'page'); else button.removeAttribute('aria-current'); });
  byId('view-title').textContent = titles[state.view]; setBanner();
  byId('scope-label').textContent = state.view === 'inventory' ? 'Inventory spans all stored sources. Active canonical identities are shown; this page is not a physical-device count.' : state.view === 'events' ? 'Events span all sources, newest first within a page · UTC · read-only' : `Collector: ${state.collector} · ${state.view === 'incidents' ? 'Retained incident evidence' : `Last ${state.hours} hours · UTC`}`;
  byId('refresh').setAttribute('aria-disabled', String(state.loading || Date.now() < client.retryAt));
  byId('content').setAttribute('aria-busy', String(state.loading));
  const retryButton = byId('notice').querySelector('button'); if (retryButton) retryButton.disabled = Date.now() < client.retryAt;
  refreshLiveLabels(byId('content'), document.hidden || interacting(), state.updated === null ? null : Date.now() / 1000 - state.updated);
  byId('refresh-status').textContent = document.hidden ? 'Refresh paused while hidden' : state.loading ? 'Refreshing…' : interacting() ? `Refresh paused while interacting · snapshot ${utc(state.updated)}` : state.updated ? `Updated ${utc(state.updated)} · refresh every 30s` : 'Refreshes every 30 seconds while visible';
}
function schedule() { clearTimeout(timer); if (state.connected && !document.hidden) timer = setTimeout(() => load(false, null, true), Math.min(2147483647, Math.max(30000, client.retryAt - Date.now()))); }
function disconnected(message = '') {
  resetReview(); client.disconnect(); state.generation++; state.connected = false; state.loading = false; state.updated = null; state.coverage = {phase: 'loading'}; state.selectedDevice = null; state.selectedIncident = null; state.eventFilter = {deviceId: '', kind: ''}; resetPage(); clearTimeout(timer);
  byId('token').value = ''; byId('content').replaceChildren(); byId('overview-probes').replaceChildren(); byId('collector').value = ''; chrome(); notice(message); byId('token').focus();
}
function selectDevice(id) { state.selectedDevice = id; load(true, '[aria-label="Identity detail"]'); }
function activity(id) { state.selectedDevice = id; navigate('activity'); }
function setInboxFilter(name) { location.hash = `#filter=${name}`; }
function selectIncident(id) { resetReview(); state.selectedIncident = id; load(true, '[aria-label="Incident evidence"]'); }
function eventsFor(id) { state.eventFilter = {deviceId: id, kind: ''}; navigate('events'); }
function filterEvents(filter) {
  if (filter.deviceId.length > 64 || filter.kind.length > 64) { notice('Filters are limited to 64 characters.'); return; }
  state.eventFilter = {deviceId: filter.deviceId, kind: filter.kind}; resetPage(); load(true, '#view-title');
}
function page(direction) {
  if (direction > 0 && state.view === 'events' && state.page + 1 >= EVENT_MAX_PAGES) return;  // hard bound, independent of the button state
  if (direction > 0 && state.next) { state.cursors[state.page + 1] = state.next; state.page++; }
  else if (direction < 0 && state.page > 0) state.page--; else return;
  resetReview(); state.selectedIncident = null; load(true, '#view-title');
}
function navigate(view) { if (!Object.hasOwn(titles, view)) return; resetReview(); state.view = view; resetPage(); load(true, '#view-title'); byId('view-title').scrollIntoView({block: 'nearest'}); }
function failure(error) {
  if (error.status === 401) { disconnected('Authentication expired or was refused. The token and observations have been cleared. Connect again with a dedicated read-only token.'); return; }
  const messages = {0: 'The API could not return valid data. Check the connection and retry.', 400: 'This source or time range was refused by the API.', 403: 'This token cannot read the requested data.', 404: 'The selected source or record was not found.', 409: 'This identity scope is currently unavailable.', 422: 'The source, identity or range is invalid.', 429: `Request limit reached. Automatic retry after ${utc(error.retryAt / 1000)}.`, 503: 'Monitoring is temporarily unavailable. Qualifying data may not be ready.'};
  const reason = messages[error.status] || 'The API request failed. Retry when the service is available.';
  notice(`${reason}${state.updated ? ` Showing the previous snapshot from ${utc(state.updated)}; it may be stale.` : ' No current observations are displayed.'}`, true);
  if (!state.updated) byId('content').replaceChildren(empty('Data unavailable', 'The interface will retry without treating missing observations as healthy.'));
}
// A failed timeline never fails the identity page, but a refused token must still disconnect (the client has already cleared it).
async function timelineFor(id) {
  try { return (await client.deviceTimeline(id)).data; }
  catch (error) { if (!(error instanceof ApiError) || error.status === 401) throw error; return null; }
}
function withTimeline(panel, events, id) { panel.append(timelineSection(events, id, eventsFor)); return panel; }
function overviewProbes(generation) {
  const message = text => node('p', {role: 'status'}, text);
  const status = node('div', {}, message('Checking probe status…'));
  byId('overview-probes').replaceChildren(
    node('section', {class: 'section'}, heading('Active probes', 'Host-wide status'), status),
  );
  // The panel settles independently so an unavailable probe view cannot delay passive coverage.
  client.probes().then(result => {
    if (generation === state.generation) status.replaceChildren(probeStatusView(result.data));
  }).catch(error => {
    if (generation !== state.generation) return;
    if (error instanceof ApiError && error.status === 401) failure(error);
    else status.replaceChildren(message('Probe status unavailable'));
  });
}
function resetReview() {
  client.disableWriter();
  pendingReview = null;
  reviewMessage = '';
  reviewSnapshotGeneration = -1;
}
function withIncidentReview(detail, generation) {
  const panel = incidentView(detail, activity);
  const {id, collector_id: collector, decision_version: version, review} = detail;
  if (id !== state.selectedIncident || collector !== state.collector || !decisionVersion(version) ||
      !['open', 'resolved', 'superseded'].includes(detail.state) ||
      (review !== null && (review?.version !== version || !['acknowledged', 'expected', 'snoozed'].includes(review.status)))) return panel;
  const controls = node('section', {class: 'section'}, node('h3', {}, 'Incident review'));
  const body = node('div');
  controls.append(body);
  panel.append(controls);
  let revision = 0;
  function render(focus = false) {
    const rendered = ++revision;
    const attached = () => rendered === revision && byId('content').contains(panel);
    const current = () => attached() && generation === reviewSnapshotGeneration && !state.loading && !document.hidden;
    const enable = (token, status) => {
      if (!current()) return;
      try {
        client.enableWriter(token, () => {
          pendingReview = null;
          reviewMessage = 'Editing expired. Check the current decision.';
          load(false);
        });
        reviewMessage = '';
        render(true);
      } catch {
        status.textContent = 'Enter a separate writer token.';
      }
    };
    const stop = () => {
      if (!attached() || pendingReview) return;
      client.disableWriter();
      reviewMessage = '';
      render(true);
    };
    const save = async (action, minutes, status, lock) => {
      if (!current() || pendingReview) return;
      if (!client.writerEnabled) { client.disableWriter(); reviewMessage = 'Editing expired.'; render(true); return; }
      if (!['acknowledge', 'mark-expected', 'snooze', 'clear'].includes(action) ||
          (action === 'clear' && review === null) || (action === 'snooze' && detail.state !== 'open')) {
        status.textContent = 'Choose an available decision.';
        return;
      }
      let until;
      if (action === 'snooze') {
        const duration = Number(minutes);
        if (!/^\d{1,5}$/.test(minutes) || duration < 2 || duration > 10080) {
          status.textContent = 'Enter a snooze duration from 2 to 10,080 minutes.';
          return;
        }
        until = new Date((Math.floor(Date.now() / 1000) + duration * 60) * 1000).toISOString().replace('.000Z', 'Z');
      }
      const pending = {};
      pendingReview = pending;
      status.textContent = 'Saving decision…';
      status.focus({preventScroll: true});
      lock();
      try {
        await client.decideIncident(id, collector, action, version, until);
        if (pending !== pendingReview) return;
        reviewMessage = 'Decision saved.';
      } catch (error) {
        if (pending !== pendingReview) return;
        if (error.status === 401 || error.status === 403) {
          pendingReview = null;
          reviewMessage = 'Writer access refused. Read access continues.';
          render(true);
          return;
        }
        if (error.status === 409) reviewMessage = 'Decision conflict. Check the latest review before applying another.';
        else if (error.status === 422 && action === 'snooze') reviewMessage = 'Snooze duration refused. Check your server’s snooze limit.';
        else reviewMessage = 'Save could not be confirmed. Check the current decision before applying another.';
      }
      pendingReview = null;
      reviewSnapshotGeneration = -1;
      status.textContent = reviewMessage;
      load(false);
    };
    body.replaceChildren(...incidentReviewControls(detail, client.writerEnabled, reviewMessage, enable, stop, save));
    if (focus) {
      body.querySelector(client.writerEnabled ? 'select' : 'input')?.focus();
      chrome();
    }
  }
  render();
  return panel;
}
async function load(clear = false, focus = null, automatic = false) {
  if (!state.connected) return;
  if (!clear && (document.hidden || pendingReview)) return;
  if (!clear && automatic && (interacting() || client.writerEnabled)) { chrome(); schedule(); return; }
  clearTimeout(timer); client.invalidate(); const generation = ++state.generation; state.loading = !document.hidden;
  if (clear) { state.updated = null; byId('overview-probes').replaceChildren(); byId('content').replaceChildren(node('p', {class: 'loading'}, 'Loading observations…')); notice(); }
  chrome();
  if (document.hidden) return;
  if (clear) (focus === '#view-title' ? byId('view-title') : byId('content')).focus({preventScroll: true});
  const focusAnchor = document.activeElement;
  let banner = null;  // coverage for non-overview views; it never rejects
  try {
    const cursor = state.cursors[state.page]; let content; let next = null; let coverage = null;
    // Non-Overview views still fetch coverage for the banner. A refused bearer ends the session.
    banner = state.view === 'overview' ? null : client.coverage(state.collector, range()).then(
      result => ({phase: 'ready', data: result.data}),
      error => {
        if (generation === state.generation && error instanceof ApiError && error.status === 401) failure(error);
        return {phase: 'error'};
      },
    );
    if (state.view === 'overview') {
      const observations = client.coverage(state.collector, range());
      overviewProbes(generation);
      const result = await observations;
      content = coverageView(result.data);
      coverage = {phase: 'ready', data: result.data};
    }
    if (state.view === 'inventory') {
      const [list, detail, timeline] = await Promise.all([client.devices(cursor), state.selectedDevice ? client.device(state.selectedDevice) : Promise.resolve(null), state.selectedDevice ? timelineFor(state.selectedDevice) : Promise.resolve(null)]);
      next = list.page?.next_cursor || null;
      const inventory = node('section', {}, heading('Tracked identities', 'Human labels are optional · unknown is a neutral classification'), inventoryView(list.data, selectDevice), pager(state.page, list.data.length, next, page), node('p', {class: 'table-note'}, 'Select an identity for DHCP names and evidence. IPs show the last observed association and time, not a current-address guarantee.'));
      content = node('div', {class: 'split'}, inventory, detail ? withTimeline(deviceView(detail.data, activity), timeline, detail.data.id) : empty('Select an identity', 'Open a row to see the observed DHCP names, classification evidence and activity. Full IDs identify inventory records, not guaranteed physical devices.'));
    }
    if (state.view === 'activity') {
      if (!state.selectedDevice) content = empty('Choose an identity to inspect', 'Open Inventory, select an identity, then choose View activity. Activity is scoped to the selected collector.');
      else { const result = await client.activity(state.selectedDevice, state.collector, range()); content = activityView(result.data); if (result.page?.next_cursor) throw new ApiError(0, 'incomplete_range'); }
    }
    if (state.view === 'events') {
      const list = await client.events(state.eventFilter, cursor);
      const rows = eventsView(list.data);  // validates the page before anything is shown
      const more = list.data.length === EVENT_PAGE && state.page + 1 < EVENT_MAX_PAGES ? list.page?.next_cursor || null : null;  // next_cursor is also sent on the last page
      next = more;
      content = node('section', {}, heading('Recent events', 'Newest first within a page, by arrival · text only · events without a device show as "No device"'), eventFilterForm(state.eventFilter, filterEvents), rows, pager(state.page, list.data.length, next, page), node('p', {class: 'table-note'}, `Showing at most ${EVENT_PAGE * EVENT_MAX_PAGES} recent events; narrow with a device or kind filter.`));
    }
    if (state.view === 'incidents') {
      const [list, detail] = await Promise.all([client.incidents(state.collector, cursor), state.selectedIncident ? client.incident(state.selectedIncident, state.collector) : Promise.resolve(null)]);
      next = list.page?.next_cursor || null;
      content = node('div', {}, node('div', {class: 'callout'}, 'Incidents describe unusual observations. An empty list does not establish normality or healthy coverage.'), node('div', {class: 'split'}, node('section', {}, heading('Retained observations', 'Collector-scoped evidence'), incidentsView(list.data, selectIncident, {filter: inboxFilter(), onFilter: setInboxFilter}), pager(state.page, inboxRows(list.data, inboxFilter()).length, next, page)), detail ? withIncidentReview(detail.data, generation) : empty('Read the evidence', 'Select an incident to inspect observed values, thresholds, coverage requirements and model provenance.')));
    }
    if (generation !== state.generation || !state.connected) return;
    const snapshot = coverage ?? await banner;  // settle first: an obsolete load must not touch shared state
    if (generation !== state.generation || !state.connected) return;
    state.coverage = snapshot;
    if (automatic && interacting()) return;  // checked after the LAST await: the user may have started using the content meanwhile
    const held = focusedInContent();
    reviewSnapshotGeneration = generation;
    state.next = next; state.updated = Date.now() / 1000; byId('content').replaceChildren(content); notice(); restoreContentFocus(held);
    if (focus && document.activeElement === focusAnchor) document.querySelector(focus)?.focus({preventScroll: true});
  } catch (error) {
    if (generation !== state.generation || error instanceof StaleResult || error.name === 'AbortError') return;
    const snapshot = state.view === 'overview' ? {phase: 'error'} : await (banner ?? Promise.resolve({phase: 'error'}));
    if (generation !== state.generation) return;
    state.coverage = snapshot;
    reviewSnapshotGeneration = -1;
    failure(error instanceof ApiError ? error : new ApiError(0, 'malformed_response'));
  } finally { if (generation === state.generation) { state.loading = false; try { chrome(); } finally { schedule(); } } }
}
byId('connect-form').addEventListener('submit', event => {
  event.preventDefault(); const token = byId('token').value.trim(); const collector = byId('connect-collector').value.trim(); byId('token').value = '';
  if (!token || !collector || collector.length > 64) { notice('Enter a collector ID and a dedicated read-only token.'); return; }
  try { client.setToken(token); state.connected = true; state.collector = collector; state.view = 'overview'; state.coverage = {phase: 'loading'}; state.selectedDevice = null; state.selectedIncident = null; state.eventFilter = {deviceId: '', kind: ''}; resetPage(); byId('collector').value = collector; byId('range').value = '24'; state.hours = 24; load(true, '#view-title'); }
  catch { disconnected('The connection inputs were invalid.'); }
});
byId('scope-form').addEventListener('submit', event => {
  event.preventDefault(); const collector = byId('collector').value.trim(); const hours = Number(byId('range').value);
  if (!collector || collector.length > 64 || ![24, 168].includes(hours)) { notice('Enter a collector ID and select a supported history range.'); return; }
  resetReview(); state.collector = collector; state.hours = hours; state.selectedIncident = null; state.coverage = {phase: 'loading'}; resetPage(); load(true, '#view-title');
});
byId('disconnect').addEventListener('click', () => disconnected());
byId('refresh').addEventListener('click', () => { if (!state.loading && Date.now() >= client.retryAt) load(false); });
document.querySelectorAll('nav button[data-view]').forEach(button => button.addEventListener('click', () => navigate(button.dataset.view)));
for (const id of ['content', 'overview-probes']) {
  byId(id).addEventListener('focusin', chrome);
  byId(id).addEventListener('focusout', () => queueMicrotask(chrome));
}
document.addEventListener('visibilitychange', () => {
  clearTimeout(timer);
  if (document.hidden) {
    const writerInput = byId('content').querySelector('[data-review-writer-token]');
    if (writerInput) writerInput.value = '';
    resetReview();
    client.invalidate(); state.generation++; state.loading = false; chrome();
  } else if (state.connected) {
    const selectedIncident = state.view === 'incidents' && state.selectedIncident !== null;
    load(false, null, !selectedIncident);
  }
});
window.addEventListener('hashchange', () => { if (state.connected && state.view === 'incidents') load(false); });
window.addEventListener('pagehide', () => disconnected());
chrome();
setInterval(() => { if (state.connected) chrome(); }, 5000);

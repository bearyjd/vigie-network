import {ApiClient, ApiError, StaleResult} from './client.js';
import {node, empty, refreshLiveLabels, heading, pager, coverageView, inventoryView, deviceView, activityView, incidentsView, incidentView, utc} from './views.js';

const byId = id => document.getElementById(id);
const client = new ApiClient();
const state = {connected: false, collector: '', hours: 24, view: 'overview', selectedDevice: null, selectedIncident: null, cursors: [null], page: 0, next: null, generation: 0, loading: false, updated: null};
let timer = null;
const titles = {overview: 'Overview', inventory: 'Inventory', activity: 'Activity', incidents: 'Incidents'};
const preview = new URLSearchParams(location.search).get('preview') === 'synthetic';
byId('preview-banner').hidden = !preview;
if (preview) byId('connect-collector').value = 'synthetic-preview';
function interacting() { return state.updated !== null && byId('content').contains(document.activeElement); }
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
  byId('connection-state').textContent = state.connected ? 'Connected · read-only view' : 'Disconnected';
  document.querySelectorAll('nav button[data-view]').forEach(button => { button.disabled = !state.connected; if (button.dataset.view === state.view && state.connected) button.setAttribute('aria-current', 'page'); else button.removeAttribute('aria-current'); });
  byId('view-title').textContent = titles[state.view];
  byId('scope-label').textContent = state.view === 'inventory' ? 'Inventory spans all stored sources. Active canonical identities are shown; this page is not a physical-device count.' : `Collector: ${state.collector} · ${state.view === 'incidents' ? 'Retained incident evidence' : `Last ${state.hours} hours · UTC`}`;
  byId('refresh').setAttribute('aria-disabled', String(state.loading || Date.now() < client.retryAt));
  byId('content').setAttribute('aria-busy', String(state.loading));
  const retryButton = byId('notice').querySelector('button'); if (retryButton) retryButton.disabled = Date.now() < client.retryAt;
  refreshLiveLabels(byId('content'), document.hidden || interacting(), state.updated === null ? null : Date.now() / 1000 - state.updated);
  byId('refresh-status').textContent = document.hidden ? 'Refresh paused while hidden' : state.loading ? 'Refreshing…' : interacting() ? `Refresh paused while interacting · snapshot ${utc(state.updated)}` : state.updated ? `Updated ${utc(state.updated)} · refresh every 30s` : 'Refreshes every 30 seconds while visible';
}
function schedule() { clearTimeout(timer); if (state.connected && !document.hidden) timer = setTimeout(() => load(false, null, true), Math.min(2147483647, Math.max(30000, client.retryAt - Date.now()))); }
function disconnected(message = '') {
  client.disconnect(); state.generation++; state.connected = false; state.loading = false; state.updated = null; state.selectedDevice = null; state.selectedIncident = null; resetPage(); clearTimeout(timer);
  byId('token').value = ''; byId('content').replaceChildren(); byId('collector').value = ''; chrome(); notice(message); byId('token').focus();
}
function selectDevice(id) { state.selectedDevice = id; load(true, '[aria-label="Identity detail"]'); }
function activity(id) { state.selectedDevice = id; navigate('activity'); }
function selectIncident(id) { state.selectedIncident = id; load(true, '[aria-label="Incident evidence"]'); }
function page(direction) {
  if (direction > 0 && state.next) { state.cursors[state.page + 1] = state.next; state.page++; }
  else if (direction < 0 && state.page > 0) state.page--; else return;
  state.selectedIncident = null; load(true, '#view-title');
}
function navigate(view) { if (!Object.hasOwn(titles, view)) return; state.view = view; resetPage(); load(true, '#view-title'); byId('view-title').scrollIntoView({block: 'nearest'}); }
function failure(error) {
  if (error.status === 401) { disconnected('Authentication expired or was refused. The token and observations have been cleared. Connect again with a dedicated read-only token.'); return; }
  const messages = {0: 'The API could not return valid data. Check the connection and retry.', 400: 'This source or time range was refused by the API.', 403: 'This token cannot read the requested data.', 404: 'The selected source or record was not found.', 409: 'This identity scope is currently unavailable.', 422: 'The source, identity or range is invalid.', 429: `Request limit reached. Automatic retry after ${utc(error.retryAt / 1000)}.`, 503: 'Monitoring is temporarily unavailable. Qualifying data may not be ready.'};
  const reason = messages[error.status] || 'The API request failed. Retry when the service is available.';
  notice(`${reason}${state.updated ? ` Showing the previous snapshot from ${utc(state.updated)}; it may be stale.` : ' No current observations are displayed.'}`, true);
  if (!state.updated) byId('content').replaceChildren(empty('Data unavailable', 'The interface will retry without treating missing observations as healthy.'));
}
async function load(clear = false, focus = null, automatic = false) {
  if (!state.connected) return;
  if (!clear && document.hidden) return;
  if (!clear && automatic && interacting()) { chrome(); schedule(); return; }
  clearTimeout(timer); client.invalidate(); const generation = ++state.generation; state.loading = !document.hidden;
  if (clear) { state.updated = null; byId('content').replaceChildren(node('p', {class: 'loading'}, 'Loading observations…')); notice(); }
  chrome();
  if (document.hidden) return;
  if (clear) (focus === '#view-title' ? byId('view-title') : byId('content')).focus({preventScroll: true});
  const focusAnchor = document.activeElement;
  try {
    const cursor = state.cursors[state.page]; let content; let next = null;
    if (state.view === 'overview') { const result = await client.coverage(state.collector, range()); content = coverageView(result.data); if (result.page?.next_cursor) throw new ApiError(0, 'incomplete_range'); }
    if (state.view === 'inventory') {
      const [list, detail] = await Promise.all([client.devices(cursor), state.selectedDevice ? client.device(state.selectedDevice) : Promise.resolve(null)]);
      next = list.page?.next_cursor || null;
      const inventory = node('section', {}, heading('Tracked identities', 'Human labels are optional · unknown is a neutral classification'), inventoryView(list.data, selectDevice), pager(state.page, list.data.length, next, page), node('p', {class: 'table-note'}, 'Select an identity for DHCP names and evidence. IPs show the last observed association and time, not a current-address guarantee.'));
      content = node('div', {class: 'split'}, inventory, detail ? deviceView(detail.data, activity) : empty('Select an identity', 'Open a row to see the observed DHCP names, classification evidence and activity. Full IDs identify inventory records, not guaranteed physical devices.'));
    }
    if (state.view === 'activity') {
      if (!state.selectedDevice) content = empty('Choose an identity to inspect', 'Open Inventory, select an identity, then choose View activity. Activity is scoped to the selected collector.');
      else { const result = await client.activity(state.selectedDevice, state.collector, range()); content = activityView(result.data); if (result.page?.next_cursor) throw new ApiError(0, 'incomplete_range'); }
    }
    if (state.view === 'incidents') {
      const [list, detail] = await Promise.all([client.incidents(state.collector, cursor), state.selectedIncident ? client.incident(state.selectedIncident, state.collector) : Promise.resolve(null)]);
      next = list.page?.next_cursor || null;
      content = node('div', {}, node('div', {class: 'callout'}, 'Incidents describe unusual observations. An empty list does not establish normality or healthy coverage.'), node('div', {class: 'split'}, node('section', {}, heading('Retained observations', 'Collector-scoped evidence'), incidentsView(list.data, selectIncident), pager(state.page, list.data.length, next, page)), detail ? incidentView(detail.data, activity) : empty('Read the evidence', 'Select an incident to inspect observed values, thresholds, coverage requirements and model provenance.')));
    }
    if (generation !== state.generation || !state.connected) return;
    if (automatic && interacting()) return;
    state.next = next; state.updated = Date.now() / 1000; byId('content').replaceChildren(content); notice();
    if (focus && document.activeElement === focusAnchor) document.querySelector(focus)?.focus({preventScroll: true});
  } catch (error) {
    if (generation !== state.generation || error instanceof StaleResult || error.name === 'AbortError') return;
    failure(error instanceof ApiError ? error : new ApiError(0, 'malformed_response'));
  } finally { if (generation === state.generation) { state.loading = false; chrome(); schedule(); } }
}
byId('connect-form').addEventListener('submit', event => {
  event.preventDefault(); const token = byId('token').value.trim(); const collector = byId('connect-collector').value.trim(); byId('token').value = '';
  if (!token || !collector || collector.length > 64) { notice('Enter a collector ID and a dedicated read-only token.'); return; }
  try { client.setToken(token); state.connected = true; state.collector = collector; state.view = 'overview'; state.selectedDevice = null; state.selectedIncident = null; resetPage(); byId('collector').value = collector; byId('range').value = '24'; state.hours = 24; load(true, '#view-title'); }
  catch { disconnected('The connection inputs were invalid.'); }
});
byId('scope-form').addEventListener('submit', event => {
  event.preventDefault(); const collector = byId('collector').value.trim(); const hours = Number(byId('range').value);
  if (!collector || collector.length > 64 || ![24, 168].includes(hours)) { notice('Enter a collector ID and select a supported history range.'); return; }
  state.collector = collector; state.hours = hours; state.selectedIncident = null; resetPage(); load(true, '#view-title');
});
byId('disconnect').addEventListener('click', () => disconnected());
byId('refresh').addEventListener('click', () => { if (!state.loading && Date.now() >= client.retryAt) load(false); });
document.querySelectorAll('nav button[data-view]').forEach(button => button.addEventListener('click', () => navigate(button.dataset.view)));
byId('content').addEventListener('focusin', chrome);
byId('content').addEventListener('focusout', () => queueMicrotask(chrome));
document.addEventListener('visibilitychange', () => { clearTimeout(timer); if (document.hidden) { client.invalidate(); state.generation++; state.loading = false; chrome(); } else if (state.connected) load(false, null, true); });
window.addEventListener('pagehide', () => disconnected());
chrome();
setInterval(() => { if (state.connected) chrome(); }, 5000);

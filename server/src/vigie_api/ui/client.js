/* Credentials live only in this module instance. Every route and verb is fixed here. */
export class ApiError extends Error {
  constructor(status, code, retryAt = 0) { super(code); this.status = status; this.code = code; this.retryAt = retryAt; }
}
export class StaleResult extends Error {}
const WRITER_LIFETIME_MS = 5 * 60 * 1000;
const decisionStatus = {acknowledge: 'acknowledged', 'mark-expected': 'expected', snooze: 'snoozed', clear: null};
export const decisionVersion = value => Number.isSafeInteger(value) && value >= 0 && value <= 1e12;
const utcSecond = value => typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value) &&
  Number.isFinite(Date.parse(value)) && new Date(value).toISOString().replace('.000Z', 'Z') === value;
const MAX_BYTES = 1048576;
const bounded = (value, size) => { if (typeof value !== 'string' || !value || value.length > size) throw new ApiError(0, 'invalid_input'); return value; };
const segment = value => { bounded(value, 64); if (value === '.' || value === '..' || /[\/\\\u0000-\u001f\u007f]/.test(value)) throw new ApiError(0, 'invalid_input'); return encodeURIComponent(value); };
export function retryTime(value, now = Date.now()) {
  if (value && /^\d+$/.test(value.trim())) return Math.min(Number.MAX_SAFE_INTEGER, now + Number(value) * 1000);
  const date = Date.parse(value || ''); return Number.isFinite(date) && date > now ? date : now + 30000;
}
async function readJson(response, limit) {
  const reader = response.body.getReader(); let size = 0; let text = ''; const decoder = new TextDecoder();
  try { while (true) { const part = await reader.read(); if (part.done) break; size += part.value.byteLength; if (size > limit) throw new ApiError(0, 'response_too_large'); text += decoder.decode(part.value, {stream: true}); } text += decoder.decode(); return JSON.parse(text); }
  catch (error) { await reader.cancel().catch(() => {}); if (error instanceof ApiError || error.name === 'AbortError') throw error; throw new ApiError(0, 'malformed_response'); }
}
export class ApiClient {
  #token = ''; #generation = 0; #controller = new AbortController(); #writer = null; retryAt = 0;
  setToken(token) { this.disconnect(); this.#token = bounded(token, 4096); this.retryAt = 0; }
  invalidate() { this.#controller.abort(); this.#controller = new AbortController(); this.#generation++; }
  disconnect() { this.invalidate(); this.disableWriter(); this.#token = ''; }
  enableWriter(token, onExpire = () => {}) {
    if (!this.#token) throw new ApiError(401, 'unauthorized');
    bounded(token, 4096);
    if (!/^[A-Za-z0-9._~-]+$/.test(token) || token === this.#token) throw new ApiError(0, 'invalid_input');
    this.disableWriter();
    this.#writer = {token, controller: new AbortController(), busy: false, retryAt: 0,
      expiresAt: Date.now() + WRITER_LIFETIME_MS,
      timer: setTimeout(() => { this.disableWriter(); onExpire(); }, WRITER_LIFETIME_MS)};
  }
  disableWriter() {
    const writer = this.#writer;
    if (!writer) return;
    this.#writer = null;
    clearTimeout(writer.timer);
    writer.controller.abort();
    writer.token = '';
  }
  get writerEnabled() { return this.#writer !== null && Date.now() < this.#writer.expiresAt; }
  #get(path, params = {}) { return this.#request(path, params); }
  async #request(path, params, writer = null, payload = null) {
    const token = writer?.token ?? this.#token;
    if (!token) throw new ApiError(401, 'unauthorized');
    const retryAt = writer?.retryAt ?? this.retryAt;
    if (Date.now() < retryAt) throw new ApiError(429, 'rate_limited', retryAt);
    const generation = this.#generation;
    const obsolete = () => writer ? writer !== this.#writer : generation !== this.#generation;
    const parent = (writer?.controller ?? this.#controller).signal;
    const request = new AbortController(); let timedOut = false;
    const abort = () => request.abort(); parent.addEventListener('abort', abort, {once: true});
    const deadline = setTimeout(() => { timedOut = true; request.abort(); }, 15000);
    const url = new URL(path, location.origin); for (const [key, value] of Object.entries(params)) if (value !== null && value !== undefined && value !== '') url.searchParams.set(key, String(value));
    try {
      const headers = {Authorization: `Bearer ${token}`, Accept: 'application/json'};
      if (writer) headers['Content-Type'] = 'application/json';
      const response = await fetch(url, {
        method: writer ? 'POST' : 'GET', headers, body: writer ? JSON.stringify(payload) : undefined,
        signal: request.signal, credentials: 'omit', cache: 'no-store', redirect: 'error',
        mode: 'same-origin', referrerPolicy: 'no-referrer',
      });
      if (obsolete()) {
        response.body?.cancel().catch(() => {});
        throw new StaleResult();
      }
      if (!response.ok) response.body?.cancel().catch(() => {});
      if (writer && [401, 403].includes(response.status)) this.disableWriter();
      if (!writer && response.status === 401) { this.disconnect(); throw new ApiError(401, 'unauthorized'); }
      if (response.status === 429) {
        const retry = retryTime(response.headers.get('Retry-After'));
        if (writer) writer.retryAt = retry; else this.retryAt = retry;
        throw new ApiError(429, 'rate_limited', retry);
      }
      if (!response.ok) throw new ApiError(response.status, 'request_failed');
      const result = await readJson(response, writer ? 4096 : MAX_BYTES);
      if (obsolete()) throw new StaleResult();
      if (!result || result.ok !== true || !Object.hasOwn(result, 'data') || !Object.hasOwn(result, 'page')) throw new ApiError(0, 'malformed_response');
      const cursor = result.page?.next_cursor;
      if (cursor !== undefined && cursor !== null && (typeof cursor !== 'string' || cursor.length > 1024)) throw new ApiError(0, 'malformed_response');
      return result;
    } catch (error) {
      if (timedOut) throw new ApiError(0, 'timeout');
      if (error instanceof ApiError || error instanceof StaleResult || error.name === 'AbortError') throw error;
      throw new ApiError(0, 'offline');
    } finally { clearTimeout(deadline); parent.removeEventListener('abort', abort); }
  }
  #monitoring(result, requested) {
    const hours = result.data?.hours;
    const count = (requested.to_hour - requested.from_hour) / 3600;
    if (result.page?.next_cursor !== null || !Array.isArray(hours) || hours.length !== count ||
        hours.some((hour, index) => !hour || hour.hour !== requested.from_hour + index * 3600)) {
      throw new ApiError(0, 'malformed_response');
    }
    return result;
  }
  #scope(collector) { return bounded(collector, 64); }
  #range(range) { if (!range || !Number.isInteger(range.from) || !Number.isInteger(range.to) || range.from < 0 || range.to <= range.from || range.to - range.from > 168 * 3600 || range.from % 3600 || range.to % 3600) throw new ApiError(0, 'invalid_input'); return {from_hour: range.from, to_hour: range.to, limit: 200}; }
  devices(cursor = null) { if (cursor !== null) bounded(cursor, 256); return this.#get('/devices', {limit: 25, cursor}); }
  device(id) { return this.#get(`/devices/${segment(id)}`); }
  coverage(collector, range) { const requested = this.#range(range); return this.#get('/coverage', {collector_id: this.#scope(collector), ...requested}).then(result => this.#monitoring(result, requested)); }
  async probes() {
    const result = await this.#get('/probes');
    if (result.page !== null) throw new ApiError(0, 'malformed_response');
    return result;
  }
  activity(id, collector, range) { const requested = this.#range(range); return this.#get(`/devices/${segment(id)}/activity`, {collector_id: this.#scope(collector), ...requested}).then(result => this.#monitoring(result, requested)); }
  incidents(collector, cursor = null) { if (cursor !== null) bounded(cursor, 1024); return this.#get('/incidents', {collector_id: this.#scope(collector), limit: 25, cursor}); }
  // Newest first, fixed page size. since/kind/device_id are bounded here to the server's own limits; limit is never caller-chosen.
  events({deviceId = '', kind = ''} = {}, cursor = null) { if (cursor !== null) bounded(cursor, 256); return this.#get('/events', {order: 'desc', limit: 25, since: cursor, kind: kind ? bounded(kind, 64) : null, device_id: deviceId ? bounded(deviceId, 64) : null}); }
  deviceTimeline(id) { return this.#get('/events', {order: 'desc', limit: 10, device_id: bounded(id, 64)}); }
  incident(id, collector) { return this.#get(`/incidents/${segment(id)}`, {collector_id: this.#scope(collector)}); }
  async decideIncident(id, collector, action, version, until = undefined) {
    if (!this.writerEnabled) { this.disableWriter(); throw new ApiError(401, 'writer_inactive'); }
    const writer = this.#writer;
    if (writer.busy) throw new ApiError(0, 'write_pending');
    if (typeof action !== 'string' || !Object.hasOwn(decisionStatus, action) || !decisionVersion(version) ||
        (action === 'snooze' ? !utcSecond(until) : until !== undefined)) throw new ApiError(0, 'invalid_input');
    const path = `/incidents/${segment(id)}/${action}`;
    const scope = this.#scope(collector);
    const payload = {expected_version: version};
    if (action === 'snooze') payload.until = until;
    writer.busy = true;
    try {
      const {data, page} = await this.#request(path, {collector_id: scope}, writer, payload);
      if (page !== null || data?.incident_id !== id || data.version !== version + 1 ||
          data.status !== decisionStatus[action] || data.snooze_until !== (until ?? null) ||
          data.decided_by !== 'app' || !utcSecond(data.decided_at)) throw new ApiError(0, 'malformed_response');
      return data;
    } finally { writer.busy = false; }
  }
}

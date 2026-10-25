/* Credentials live only in this module instance. Every route and verb is fixed here. */
export class ApiError extends Error {
  constructor(status, code, retryAt = 0) { super(code); this.status = status; this.code = code; this.retryAt = retryAt; }
}
export class StaleResult extends Error {}
const MAX_BYTES = 1048576;
const bounded = (value, size) => { if (typeof value !== 'string' || !value || value.length > size) throw new ApiError(0, 'invalid_input'); return value; };
const segment = value => { bounded(value, 64); if (value === '.' || value === '..' || /[\/\\\u0000-\u001f\u007f]/.test(value)) throw new ApiError(0, 'invalid_input'); return encodeURIComponent(value); };
export function retryTime(value, now = Date.now()) {
  if (value && /^\d+$/.test(value.trim())) return Math.min(Number.MAX_SAFE_INTEGER, now + Number(value) * 1000);
  const date = Date.parse(value || ''); return Number.isFinite(date) && date > now ? date : now + 30000;
}
async function readJson(response) {
  const reader = response.body.getReader(); let size = 0; let text = ''; const decoder = new TextDecoder();
  try { while (true) { const part = await reader.read(); if (part.done) break; size += part.value.byteLength; if (size > MAX_BYTES) throw new ApiError(0, 'response_too_large'); text += decoder.decode(part.value, {stream: true}); } text += decoder.decode(); return JSON.parse(text); }
  catch (error) { await reader.cancel().catch(() => {}); if (error instanceof ApiError || error.name === 'AbortError') throw error; throw new ApiError(0, 'malformed_response'); }
}
export class ApiClient {
  #token = ''; #generation = 0; #controller = new AbortController(); retryAt = 0;
  setToken(token) { this.disconnect(); this.#token = bounded(token, 4096); this.retryAt = 0; }
  invalidate() { this.#controller.abort(); this.#controller = new AbortController(); this.#generation++; }
  disconnect() { this.invalidate(); this.#token = ''; }
  async #get(path, params = {}) {
    if (!this.#token) throw new ApiError(401, 'unauthorized');
    if (Date.now() < this.retryAt) throw new ApiError(429, 'rate_limited', this.retryAt);
    const generation = this.#generation; const parent = this.#controller.signal;
    const request = new AbortController(); let timedOut = false;
    const abort = () => request.abort(); parent.addEventListener('abort', abort, {once: true});
    const deadline = setTimeout(() => { timedOut = true; request.abort(); }, 15000);
    const url = new URL(path, location.origin); for (const [key, value] of Object.entries(params)) if (value !== null && value !== undefined && value !== '') url.searchParams.set(key, String(value));
    try {
      const response = await fetch(url, {method: 'GET', headers: {Authorization: `Bearer ${this.#token}`, Accept: 'application/json'}, signal: request.signal, credentials: 'omit', cache: 'no-store', redirect: 'error', mode: 'same-origin', referrerPolicy: 'no-referrer'});
      if (generation !== this.#generation) throw new StaleResult();
      if (response.status === 401) { this.disconnect(); throw new ApiError(401, 'unauthorized'); }
      if (response.status === 429) { this.retryAt = retryTime(response.headers.get('Retry-After')); throw new ApiError(429, 'rate_limited', this.retryAt); }
      if (!response.ok) throw new ApiError(response.status, 'request_failed');
      const result = await readJson(response);
      if (generation !== this.#generation) throw new StaleResult();
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
  #scope(collector) { return bounded(collector, 64); }
  #range(range) { if (!range || !Number.isInteger(range.from) || !Number.isInteger(range.to) || range.from < 0 || range.to <= range.from || range.to - range.from > 168 * 3600 || range.from % 3600 || range.to % 3600) throw new ApiError(0, 'invalid_input'); return {from_hour: range.from, to_hour: range.to, limit: 200}; }
  devices(cursor = null) { if (cursor !== null) bounded(cursor, 256); return this.#get('/devices', {limit: 25, cursor}); }
  device(id) { return this.#get(`/devices/${segment(id)}`); }
  coverage(collector, range) { return this.#get('/coverage', {collector_id: this.#scope(collector), ...this.#range(range)}); }
  activity(id, collector, range) { return this.#get(`/devices/${segment(id)}/activity`, {collector_id: this.#scope(collector), ...this.#range(range)}); }
  incidents(collector, cursor = null) { if (cursor !== null) bounded(cursor, 1024); return this.#get('/incidents', {collector_id: this.#scope(collector), limit: 25, cursor}); }
  incident(id, collector) { return this.#get(`/incidents/${segment(id)}`, {collector_id: this.#scope(collector)}); }
}

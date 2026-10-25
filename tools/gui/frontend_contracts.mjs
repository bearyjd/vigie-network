// Offline contracts; Node 22.7+ or the existing Playwright driver/node. No packages required.
// Run from any directory: node /path/to/repository/tools/gui/frontend_contracts.mjs
import assert from 'node:assert/strict';
import {ApiClient,ApiError,StaleResult,retryTime} from '../../server/src/vigie_api/ui/client.js';
import {processingState,coverageView,liveLabel,refreshLiveLabels} from '../../server/src/vigie_api/ui/views.js';
globalThis.location={origin:'http://127.0.0.1:18745'};
const tick=()=>new Promise(resolve=>setImmediate(resolve));
const now=Date.parse('2026-10-25T12:00:00Z');
assert.equal(processingState({backlog_batches:0,backlog_capped:false,oldest_pending_received_at:null},now).label,'Drained');
for(const c of [{backlog_batches:0,backlog_capped:true,oldest_pending_received_at:null},{backlog_batches:1,backlog_capped:false,oldest_pending_received_at:null},{backlog_batches:0,backlog_capped:false},{backlog_batches:1,backlog_capped:false,oldest_pending_received_at:'2026-10-25T12:00:01Z'}])assert.equal(processingState(c,now).label,'Unknown');
assert.equal(processingState({backlog_batches:1,backlog_capped:false,oldest_pending_received_at:'2026-10-25T11:59:00Z'},now).label,'Awaiting processing');
assert.equal(processingState({backlog_batches:1,backlog_capped:false,oldest_pending_received_at:'2026-10-25T11:56:59Z'},now).label,'Stalled');
assert.equal(retryTime('90000',0),90000000);
const api=new ApiClient();api.setToken('synthetic-test-token');
for(const id of ['.','..','a/b','a\\b','a\n'])assert.throws(()=>api.device(id),ApiError);
let calls=[];
globalThis.fetch=async(url,opts)=>{calls.push({url:String(url),method:opts.method,cache:opts.cache,credentials:opts.credentials,redirect:opts.redirect});return new Response(JSON.stringify({ok:true,data:[],page:{next_cursor:null}}));};
await api.devices();assert.equal(calls[0].method,'GET');assert.equal(calls[0].credentials,'omit');assert.equal(calls[0].redirect,'error');assert.equal(calls[0].cache,'no-store');assert.equal(new URL(calls[0].url).pathname,'/devices');
let release;globalThis.fetch=()=>new Promise(resolve=>release=resolve);
const stale=api.devices();api.invalidate();release(new Response(JSON.stringify({ok:true,data:[],page:null})));await assert.rejects(stale,StaleResult);
globalThis.fetch=async()=>new Response('',{status:401});await assert.rejects(api.devices(),e=>e.status===401);await assert.rejects(api.devices(),e=>e.status===401);

// Error bodies must release their stream even though the UI never renders their content.
for (const status of [401, 429, 503]) {
  const c = new ApiClient(); c.setToken('synthetic-only'); let cancelled = false;
  globalThis.fetch = async () => new Response(new ReadableStream({
    start(controller) { controller.enqueue(new TextEncoder().encode('{"ok":false}')); },
    cancel() { cancelled = true; },
  }), {status, headers: {'Retry-After': '60'}});
  await assert.rejects(c.devices(), error => error.status === status);
  assert.equal(cancelled, true, `HTTP ${status} left its response stream open`);
}
const capped = new ApiClient(); capped.setToken('synthetic-only'); let capCancelled = false;
globalThis.fetch = async () => new Response(new ReadableStream({
  start(controller) { controller.enqueue(new Uint8Array(1048577)); },
  cancel() { capCancelled = true; },
}));
await assert.rejects(capped.devices(), error => error.code === 'response_too_large');
assert.equal(capCancelled, true);
assert.equal(retryTime('Sun, 25 Oct 2026 12:05:00 GMT', now), now + 300000);
assert.equal(retryTime('invalid', now), now + 30000);
assert.equal(retryTime('9'.repeat(400), now), Number.MAX_SAFE_INTEGER);

// Both monitoring endpoints return a full UTC grid; absent metrics remain null.
const requested = {from: 0, to: 86400};
const grid = Array.from({length: 24}, (_, i) => ({hour: i * 3600, state: 'missing',
  observed_seconds: null, qualified_seconds: null, reasons: ['missing'],
  bytes_up: null, bytes_down: null, flows: null, dns_queries: null}));
for (const kind of ['coverage', 'activity']) {
  const c = new ApiClient(); c.setToken('synthetic-only');
  const call = range => kind === 'coverage' ? c.coverage('synthetic-preview', range)
    : c.activity('synthetic-identity', 'synthetic-preview', range);
  globalThis.fetch = async () => new Response(JSON.stringify({ok: true, page: {next_cursor: null}, data: {hours: grid}}));
  assert.deepEqual((await call(requested)).data.hours, grid);
  for (const hours of [[], grid.slice(1), [...grid, {...grid.at(-1), hour: 86400}],
    grid.map((h, i) => i === 1 ? {...h, hour: 0} : h), [...grid].reverse()]) {
    globalThis.fetch = async () => new Response(JSON.stringify({ok: true, page: {next_cursor: null}, data: {hours}}));
    await assert.rejects(call(requested), error => error.code === 'malformed_response',
      `${kind} accepted an incomplete, duplicated or unordered UTC grid`);
  }
  globalThis.fetch = async () => new Response(JSON.stringify({ok: true, page: {next_cursor: 'unexpected'}, data: {hours: grid}}));
  await assert.rejects(call(requested), error => error.code === 'malformed_response');
  let finish; globalThis.fetch = () => new Promise(resolve => finish = resolve);
  const mutable = {...requested}; const pending = call(mutable); mutable.to += 3600;
  finish(new Response(JSON.stringify({ok: true, page: {next_cursor: null}, data: {hours: grid}})));
  assert.equal((await pending).data.hours.length, 24, 'response validation used a later range');
}


// A response whose body finishes after invalidate()/disconnect must never be delivered.
{
  const c=new ApiClient();c.setToken('synthetic-only');let release;
  globalThis.fetch=async()=>new Response(new ReadableStream({start(controller){release=()=>{controller.enqueue(new TextEncoder().encode(JSON.stringify({ok:true,data:[],page:{next_cursor:null}})));controller.close();};}}));
  const pending=c.devices();await tick();await tick();c.invalidate();release();
  await assert.rejects(pending,e=>e instanceof StaleResult,'body completed after invalidate was delivered');
}
// The view layer re-validates the UTC grid itself: a numeric string passes `% 3600`, so the integer check is not dead.
for(const hour of ['7200',7200.5,3601,-3600,null])assert.throws(()=>coverageView({collector:{},hours:[{hour,state:'missing',reasons:[]}]}),/Malformed monitoring response/,`hour ${String(hour)} accepted`);
// 'Current' is only claimed for a fresh, live, unpaused snapshot.
assert.equal(liveLabel(true,false,5),'Current');
assert.equal(liveLabel(true,true,5),'Snapshot (paused)');
assert.equal(liveLabel(true,false,121),'Stale');assert.equal(liveLabel(true,true,121),'Stale');assert.equal(liveLabel(true,false,null),'Stale');
assert.equal(liveLabel(true,false,120),'Current');
assert.equal(liveLabel(false,false,5),'Stale / unknown');assert.equal(liveLabel(false,true,5),'Stale / unknown');
// M2: the observation itself ages; a young snapshot of an aged observation is not 'Current'.
assert.equal(liveLabel(true,false,5,121),'Stale');assert.equal(liveLabel(true,true,5,121),'Stale');
assert.equal(liveLabel(true,false,5,120),'Current');assert.equal(liveLabel(true,false,5,null),'Stale');
assert.equal(liveLabel(false,false,5,500),'Stale / unknown');
// L3: a client clock stepped backwards yields negative ages; that is unknown freshness, never 'Current'.
assert.equal(liveLabel(true,false,-1),'Stale');assert.equal(liveLabel(true,true,-1),'Stale');
assert.equal(liveLabel(true,false,5,-1),'Stale');assert.equal(liveLabel(true,true,5,-0.5),'Stale');
assert.equal(liveLabel(true,false,0,0),'Current');assert.equal(liveLabel(false,false,-1,-1),'Stale / unknown');
{
  const label = (observed, snapshotAge = 5) => {
    const el = {textContent: '', getAttribute: name => ({'data-live-current': 'true', 'data-live-observed': observed})[name]};
    refreshLiveLabels({querySelectorAll: () => [el]}, false, snapshotAge, 1000);
    return el.textContent;
  };
  assert.equal(label('990'), 'Current'); assert.equal(label('1000'), 'Current');
  assert.equal(label('1001'), 'Stale'); assert.equal(label('5000'), 'Stale');
  assert.equal(label('800'), 'Stale'); assert.equal(label(''), 'Stale'); assert.equal(label('990', -3), 'Stale');
}

// Deadline failures are surfaced and cleaned up without a real 15-second wait.
const originalSetTimeout = globalThis.setTimeout; const originalClearTimeout = globalThis.clearTimeout;
let expire; let deadlineCleared = false;
try {
  globalThis.setTimeout = callback => { expire = callback; return 123; };
  globalThis.clearTimeout = timer => { assert.equal(timer, 123); deadlineCleared = true; };
  const c = new ApiClient(); c.setToken('synthetic-only');
  globalThis.fetch = (url, options) => new Promise((resolve, reject) => {
    options.signal.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')));
  });
  const pending = c.devices(); expire();
  await assert.rejects(pending, error => error.code === 'timeout');
  assert.equal(deadlineCleared, true);
} finally { globalThis.setTimeout = originalSetTimeout; globalThis.clearTimeout = originalClearTimeout; }
console.log('PASS: fixed GET/generation/auth/backlog contracts; complete UTC grids with null gaps; bounded/cancelled bodies and deadlines; numeric/HTTP-date Retry-After.');

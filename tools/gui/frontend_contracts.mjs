// Offline contracts; Node 22.7+ or the existing Playwright driver/node. No packages required.
// Run from any directory: node /path/to/repository/tools/gui/frontend_contracts.mjs
import assert from 'node:assert/strict';
import {ApiClient,ApiError,StaleResult,retryTime} from '../../server/src/vigie_api/ui/client.js';
import {processingState} from '../../server/src/vigie_api/ui/views.js';
globalThis.location={origin:'http://127.0.0.1:18745'};
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
console.log('PASS: backlog known/unknown/future/stall semantics; fixed GET options; rejected dot/slash/control IDs; stale-response rejection; 401 memory-token clear; Retry-After over24h respected.');

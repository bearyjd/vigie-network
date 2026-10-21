//! Send engine: drains the spool oldest-first through a `Transport`, re-stamping and re-signing
//! on every attempt, with backoff, time-sanity hold and per-status handling.

use crate::backoff::Backoff;
use crate::model::EncodedBatch;
use crate::sign;
use crate::spool::Spool;
use crate::timegate::TimeGate;

/// Server rule: `window_end` older than `sent_ts` by more than this is rejected (422).
pub const MAX_SPOOL_AGE_S: u64 = 24 * 3600;

#[derive(Debug, Clone)]
pub struct Identity {
    pub collector_id: String,
    pub key_id: String,
    pub boot_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Headers {
    pub collector_id: String,
    pub key_id: String,
    pub boot_id: String,
    pub seq: String,
    pub sent_ts: String,
    pub batch_id: String,
    pub signature: String,
}

impl Headers {
    pub fn pairs(&self) -> [(&'static str, &str); 7] {
        [
            ("X-Vigie-Collector-Id", &self.collector_id),
            ("X-Vigie-Key-Id", &self.key_id),
            ("X-Vigie-Boot-Id", &self.boot_id),
            ("X-Vigie-Seq", &self.seq),
            ("X-Vigie-Sent-Ts", &self.sent_ts),
            ("X-Vigie-Batch-Id", &self.batch_id),
            ("X-Vigie-Signature", &self.signature),
        ]
    }
}

#[derive(Debug, Clone)]
pub struct HttpReply {
    pub status: u16,
    /// Server `Date` header as epoch seconds, when present and parseable.
    pub date: Option<u64>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportError(pub String);

/// HTTPS boundary. The production implementation (SPKI-pinned TLS) is NOT written yet.
pub trait Transport {
    fn post(&mut self, headers: &Headers, body: &[u8]) -> Result<HttpReply, TransportError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tick {
    Idle,
    Held,
    Waiting,
    Sent { duplicate: bool },
    Discarded(u16),
    DiscardedStale,
    Retry { status: Option<u16>, delay_s: u64 },
}

pub struct Engine {
    pub spool: Spool,
    pub backoff: Backoff,
    pub gate: TimeGate,
    pub dropped_stale: u64,
    id: Identity,
    key: Vec<u8>,
    next_attempt_s: u64,
}

impl Engine {
    pub fn new(id: Identity, key: Vec<u8>, build_ts: u64, spool_cap: usize) -> Self {
        Self {
            spool: Spool::new(spool_cap),
            backoff: Backoff::default(),
            gate: TimeGate::new(build_ts),
            dropped_stale: 0,
            id,
            key,
            next_attempt_s: 0,
        }
    }

    pub fn enqueue(&mut self, b: EncodedBatch) {
        self.spool.push(b);
    }

    /// Try to send the oldest spooled batch. `wall_ts` is the (possibly wrong) wall clock,
    /// `mono_s` a monotonic clock, `rand` jitter entropy.
    pub fn tick<T: Transport>(&mut self, t: &mut T, wall_ts: u64, mono_s: u64, rand: u64) -> Tick {
        let Some(front) = self.spool.front() else {
            return Tick::Idle;
        };
        if !self.gate.is_sane(wall_ts, mono_s) {
            return Tick::Held;
        }
        if mono_s < self.next_attempt_s {
            return Tick::Waiting;
        }
        let dropped = self.spool.dropped_unreported();
        let body = front.body(wall_ts, dropped);
        let env = sign::Envelope {
            collector_id: &self.id.collector_id,
            key_id: &self.id.key_id,
            boot_id: &self.id.boot_id,
            seq: front.seq,
            sent_ts: wall_ts,
            batch_id: &front.batch_id,
        };
        let headers = Headers {
            collector_id: self.id.collector_id.clone(),
            key_id: self.id.key_id.clone(),
            boot_id: self.id.boot_id.clone(),
            seq: front.seq.to_string(),
            sent_ts: wall_ts.to_string(),
            batch_id: front.batch_id.clone(),
            signature: sign::sign(&self.key, &env, &body),
        };
        match t.post(&headers, &body) {
            Ok(reply) => self.on_reply(reply, dropped, wall_ts, mono_s, rand),
            Err(_) => self.retry(None, mono_s, rand),
        }
    }

    fn on_reply(
        &mut self,
        reply: HttpReply,
        dropped: u64,
        wall_ts: u64,
        mono_s: u64,
        rand: u64,
    ) -> Tick {
        if let Some(date) = reply.date {
            self.gate.observe_server_date(date, mono_s);
        }
        match reply.status {
            // 200 covers both `{"duplicate":false}` and `{"duplicate":true}` (lost-ACK retry):
            // either way the server has the batch.
            200 => {
                let duplicate = body_says_duplicate(&reply.body);
                self.spool.pop_front();
                self.spool.mark_reported(dropped);
                self.backoff.reset();
                self.next_attempt_s = mono_s;
                Tick::Sent { duplicate }
            }
            // The server will never accept this batch: discard it so it cannot block the queue.
            status @ (409 | 413 | 422) => {
                let stale = status == 422
                    && self
                        .spool
                        .front()
                        .is_some_and(|b| b.window_end.saturating_add(MAX_SPOOL_AGE_S) < wall_ts);
                self.spool.pop_front();
                self.spool.note_dropped(1);
                if stale {
                    // The server's 422 body does not say why, so staleness is judged locally.
                    self.dropped_stale = self.dropped_stale.saturating_add(1);
                    return Tick::DiscardedStale;
                }
                Tick::Discarded(status)
            }
            status => self.retry(Some(status), mono_s, rand),
        }
    }

    fn retry(&mut self, status: Option<u16>, mono_s: u64, rand: u64) -> Tick {
        let delay_s = self.backoff.next_delay_s(rand);
        self.next_attempt_s = mono_s.saturating_add(delay_s);
        Tick::Retry { status, delay_s }
    }
}

fn body_says_duplicate(body: &[u8]) -> bool {
    String::from_utf8_lossy(body)
        .replace(' ', "")
        .contains("\"duplicate\":true")
}

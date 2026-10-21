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

/// Wipes the HMAC key when the engine goes away.
impl Drop for Engine {
    fn drop(&mut self) {
        crate::config::wipe(&mut self.key);
    }
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
                // A duplicate reply means the server kept the first attempt and ignored this
                // retry's `dropped_batches`: only a fresh batch acknowledges what it carried.
                if !duplicate {
                    self.spool.mark_reported(dropped);
                }
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

/// True only if the body is one JSON object whose top-level `"duplicate"` member is `true`.
/// Nested keys and string contents are skipped, not searched; a repeated `"duplicate"` key, a
/// non-boolean value, malformed JSON, trailing bytes or nesting deeper than `MAX_DEPTH` all give
/// false (the server's reply is then treated as a fresh acceptance).
pub fn body_says_duplicate(body: &[u8]) -> bool {
    let mut p = Scan { b: body, i: 0 };
    p.top_level_duplicate().unwrap_or(false)
}

const MAX_DEPTH: usize = 32;

struct Scan<'a> {
    b: &'a [u8],
    i: usize,
}

impl Scan<'_> {
    fn ws(&mut self) {
        while matches!(self.b.get(self.i), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }

    fn eat(&mut self, c: u8) -> Option<()> {
        self.ws();
        (self.b.get(self.i) == Some(&c)).then(|| self.i += 1)
    }

    fn peek(&mut self) -> Option<u8> {
        self.ws();
        self.b.get(self.i).copied()
    }

    fn top_level_duplicate(&mut self) -> Option<bool> {
        self.eat(b'{')?;
        let mut found: Option<bool> = None;
        if self.peek()? == b'}' {
            self.i += 1;
        } else {
            loop {
                let key = self.string()?;
                self.eat(b':')?;
                if key == b"duplicate" {
                    let v = self.boolean()?;
                    if found.replace(v).is_some() {
                        return None;
                    }
                } else {
                    self.value(1)?;
                }
                match self.peek()? {
                    b',' => self.i += 1,
                    b'}' => {
                        self.i += 1;
                        break;
                    }
                    _ => return None,
                }
            }
        }
        self.ws();
        (self.i == self.b.len()).then_some(found.unwrap_or(false))
    }

    fn boolean(&mut self) -> Option<bool> {
        self.ws();
        for (lit, v) in [(&b"true"[..], true), (&b"false"[..], false)] {
            if self.b[self.i..].starts_with(lit) {
                self.i += lit.len();
                return Some(v);
            }
        }
        None
    }

    /// A string; returns its unescaped bytes. Raw control characters are malformed JSON.
    fn string(&mut self) -> Option<Vec<u8>> {
        self.eat(b'"')?;
        let mut out = Vec::new();
        loop {
            let c = *self.b.get(self.i)?;
            self.i += 1;
            match c {
                b'"' => return Some(out),
                0..=0x1f => return None,
                b'\\' => {
                    let e = *self.b.get(self.i)?;
                    self.i += 1;
                    match e {
                        b'"' | b'\\' | b'/' => out.push(e),
                        b'b' => out.push(8),
                        b'f' => out.push(12),
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'u' => {
                            let hex = self.b.get(self.i..self.i + 4)?;
                            self.i += 4;
                            let n = u32::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok()?;
                            let ch = char::from_u32(n).unwrap_or(char::REPLACEMENT_CHARACTER);
                            out.extend_from_slice(ch.encode_utf8(&mut [0; 4]).as_bytes());
                        }
                        _ => return None,
                    }
                }
                _ => out.push(c),
            }
        }
    }

    fn value(&mut self, depth: usize) -> Option<()> {
        if depth > MAX_DEPTH {
            return None;
        }
        match self.peek()? {
            b'"' => self.string().map(drop),
            b'{' => {
                self.i += 1;
                self.members(b'}', depth, true)
            }
            b'[' => {
                self.i += 1;
                self.members(b']', depth, false)
            }
            b't' | b'f' => self.boolean().map(drop),
            b'n' => self.b[self.i..].starts_with(b"null").then(|| self.i += 4),
            b'-' | b'0'..=b'9' => {
                let start = self.i;
                while matches!(
                    self.b.get(self.i),
                    Some(b'0'..=b'9' | b'+' | b'-' | b'.' | b'e' | b'E')
                ) {
                    self.i += 1;
                }
                (self.i > start).then_some(())
            }
            _ => None,
        }
    }

    /// Members of an object (`keyed`) or elements of an array, after the opening bracket.
    fn members(&mut self, close: u8, depth: usize, keyed: bool) -> Option<()> {
        if self.peek()? == close {
            self.i += 1;
            return Some(());
        }
        loop {
            if keyed {
                self.string()?;
                self.eat(b':')?;
            }
            self.value(depth + 1)?;
            match self.peek()? {
                b',' => self.i += 1,
                c if c == close => {
                    self.i += 1;
                    return Some(());
                }
                _ => return None,
            }
        }
    }
}

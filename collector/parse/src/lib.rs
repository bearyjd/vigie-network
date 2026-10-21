#![forbid(unsafe_code)]
//! Bounds-checked parsers for LAN-supplied multicast data (mDNS wire format, SSDP).

pub mod mdns;
pub mod ssdp;

/// Characters replaced with '?' in anything we retain: controls, bidi overrides/isolates and
/// line/paragraph separators (they can reorder or hide text when evidence is displayed).
pub(crate) fn is_unsafe_char(c: char) -> bool {
    c.is_control()
        || matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{2028}' | '\u{2029}')
}

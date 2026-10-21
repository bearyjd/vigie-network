//! Tiny JSON string writer (no serde on the router). Output is always valid UTF-8 JSON.

use std::fmt::Write;

/// Append `s` as a JSON string literal (quotes included).
pub fn push_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || c == '\u{7f}' => {
                // Writing to a String cannot fail.
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// `"key":` prefix with a leading comma unless this is the first member.
pub fn key(out: &mut String, first: bool, name: &str) {
    if !first {
        out.push(',');
    }
    push_str(out, name);
    out.push(':');
}

pub fn push_opt_str(out: &mut String, v: Option<&str>) {
    match v {
        Some(s) => push_str(out, s),
        None => out.push_str("null"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc(s: &str) -> String {
        let mut o = String::new();
        push_str(&mut o, s);
        o
    }

    #[test]
    fn escapes_quotes_backslash_and_controls() {
        assert_eq!(enc("a\"b\\c"), r#""a\"b\\c""#);
        assert_eq!(enc("l1\nl2\r\t"), r#""l1\nl2\r\t""#);
        assert_eq!(enc("\u{0}\u{1f}\u{7f}"), r#""\u0000\u001f\u007f""#);
    }

    #[test]
    fn passes_unicode_through() {
        assert_eq!(enc("caf\u{e9} \u{1f600}"), "\"caf\u{e9} \u{1f600}\"");
    }

    #[test]
    fn option_and_key_helpers() {
        let mut o = String::new();
        key(&mut o, true, "a");
        push_opt_str(&mut o, None);
        key(&mut o, false, "b");
        push_opt_str(&mut o, Some("x"));
        assert_eq!(o, r#""a":null,"b":"x""#);
    }
}

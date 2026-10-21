//! MAC address normalization to the schema form `^[0-9a-f]{2}(:[0-9a-f]{2}){5}$`.

/// Accepts six 2-digit hex groups separated by `:` or `-` (any case). Rejects the all-zero
/// and broadcast addresses, which never identify a device.
pub fn normalize(s: &str) -> Option<String> {
    let s = s.trim();
    if s.len() != 17 || !s.is_ascii() {
        return None;
    }
    let mut out = String::with_capacity(17);
    let mut all_zero = true;
    let mut all_ff = true;
    for (i, group) in s.split([':', '-']).enumerate() {
        if group.len() != 2 || !group.bytes().all(|b| b.is_ascii_hexdigit()) || i > 5 {
            return None;
        }
        let g = group.to_ascii_lowercase();
        all_zero &= g == "00";
        all_ff &= g == "ff";
        if i > 0 {
            out.push(':');
        }
        out.push_str(&g);
    }
    // 6 groups of 2 plus 5 separators is 17 bytes, and every separator was consumed by split.
    if out.len() != 17 || all_zero || all_ff {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lowercases_and_converts_dashes() {
        assert_eq!(
            normalize("AA:BB:cc:0D:0e:0F").as_deref(),
            Some("aa:bb:cc:0d:0e:0f")
        );
        assert_eq!(
            normalize("AA-BB-CC-DD-EE-FF").as_deref(),
            Some("aa:bb:cc:dd:ee:ff")
        );
        assert_eq!(
            normalize("  aa:bb:cc:dd:ee:01\n").as_deref(),
            Some("aa:bb:cc:dd:ee:01")
        );
    }

    #[test]
    fn rejects_malformed_zero_and_broadcast() {
        for bad in [
            "",
            "aa:bb:cc:dd:ee",
            "aa:bb:cc:dd:ee:ff:00",
            "aa:bb:cc:dd:ee:0g",
            "aabb.ccdd.eeff",
            "a:bb:cc:dd:ee:ff:",
            "00:00:00:00:00:00",
            "ff:ff:ff:ff:ff:ff",
            "aa:bb:cc:dd:ee:f\u{e9}",
            "aa:bb-cc:dd:ee:01x",
        ] {
            assert_eq!(normalize(bad), None, "{bad:?}");
        }
    }
}

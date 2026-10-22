//! HTTP `Date` header (IMF-fixdate, e.g. `Tue, 20 Oct 2026 21:59:38 GMT`) to epoch seconds.

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

/// Sanity bound on the year, not part of the RFC: the agent only uses the server's clock to judge
/// its own, and a date outside this window is a broken or hostile reply, never a real time.
const YEARS: std::ops::RangeInclusive<i64> = 2020..=2100;

/// Exactly `Sun, 06 Nov 1994 08:49:37 GMT` (RFC 9110 5.6.7 IMF-fixdate): 29 bytes, single spaces,
/// two-digit day, four-digit year, case-sensitive names, `GMT`. The weekday must match the date
/// and the date must exist; seconds are 0-59 (a leap second `60` is refused); the year must lie in
/// 2020..=2100. The obsolete RFC 850 and asctime forms are not accepted. Anything else is `None`.
pub fn parse_imf_fixdate(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    let fixed = |i: usize, c: u8| b.get(i) == Some(&c);
    if b.len() != 29
        || !(fixed(3, b',') && fixed(4, b' ') && fixed(7, b' ') && fixed(11, b' '))
        || !(fixed(16, b' ') && fixed(19, b':') && fixed(22, b':') && fixed(25, b' '))
        || &b[26..] != b"GMT"
    {
        return None;
    }
    let num = |from: usize, to: usize| -> Option<i64> {
        let digits = &b[from..to];
        digits.iter().all(u8::is_ascii_digit).then(|| {
            digits
                .iter()
                .fold(0i64, |n, d| n * 10 + i64::from(d - b'0'))
        })
    };
    let weekday = DAYS.iter().position(|d| d.as_bytes() == &b[..3])? as i64;
    let day = num(5, 7)?;
    let month = MONTHS.iter().position(|m| m.as_bytes() == &b[8..11])? as i64 + 1;
    let year = num(12, 16)?;
    let (h, mi, sec) = (num(17, 19)?, num(20, 22)?, num(23, 25)?);
    if !YEARS.contains(&year) || h > 23 || mi > 59 || sec > 59 {
        return None;
    }
    if !(1..=days_in_month(year, month)).contains(&day) {
        return None;
    }
    let days = days_from_civil(year, month, day);
    // 1970-01-01 was a Thursday (4).
    if (days + 4).rem_euclid(7) != weekday {
        return None;
    }
    u64::try_from(days * 86_400 + h * 3600 + mi * 60 + sec).ok()
}

fn days_in_month(year: i64, month: i64) -> i64 {
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_dates() {
        assert_eq!(
            parse_imf_fixdate("Tue, 20 Oct 2026 21:59:38 GMT"),
            Some(1_792_533_578)
        );
        assert_eq!(
            parse_imf_fixdate("Thu, 29 Feb 2024 12:00:00 GMT"),
            Some(1_709_208_000)
        );
    }

    #[test]
    fn rejects_garbage() {
        for bad in [
            "",
            "Tue, 20 Oct 2026 21:59:38 UTC",
            "Tue, 20 Foo 2026 21:59:38 GMT",
            "Tue, 32 Oct 2026 21:59:38 GMT",
            "Tue, 20 Oct 2026 24:59:38 GMT",
            "Tue, 20 Oct 2026 21:59 GMT",
            "20 Oct 2026 21:59:38 GMT",
            "Mon, 20 Oct 1969 21:59:38 GMT",
            "\u{0}\u{1}",
        ] {
            assert_eq!(parse_imf_fixdate(bad), None, "{bad:?}");
        }
    }
}

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

pub fn parse_imf_fixdate(s: &str) -> Option<u64> {
    let t: Vec<&str> = s.split_whitespace().collect();
    if t.len() != 6 || t[5] != "GMT" || !t[0].ends_with(',') {
        return None;
    }
    let day: i64 = t[1].parse().ok()?;
    let month = MONTHS.iter().position(|m| *m == t[2])? as i64 + 1;
    let year: i64 = t[3].parse().ok()?;
    let mut hms = t[4].split(':');
    let (h, mi, sec): (i64, i64, i64) = (
        hms.next()?.parse().ok()?,
        hms.next()?.parse().ok()?,
        hms.next()?.parse().ok()?,
    );
    if hms.next().is_some()
        || !(1..=31).contains(&day)
        || !(1970..=9999).contains(&year)
        || h > 23
        || mi > 59
        || sec > 60
    {
        return None;
    }
    let secs = days_from_civil(year, month, day) * 86_400 + h * 3600 + mi * 60 + sec;
    u64::try_from(secs).ok()
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
        assert_eq!(parse_imf_fixdate("Thu, 01 Jan 1970 00:00:00 GMT"), Some(0));
        assert_eq!(
            parse_imf_fixdate("Tue, 29 Feb 2000 12:00:00 GMT"),
            Some(951_825_600)
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
            "Tue, 20 Oct 1969 21:59:38 GMT",
            "\u{0}\u{1}",
        ] {
            assert_eq!(parse_imf_fixdate(bad), None, "{bad:?}");
        }
    }
}

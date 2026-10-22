//! Strict IMF-fixdate (RFC 9110 5.6.7) parsing and the first-Date-header-only rule.

use vigie_agent::httpdate::parse_imf_fixdate;

#[test]
fn accepts_well_formed_dates_in_range() {
    for (s, epoch) in [
        ("Tue, 20 Oct 2026 21:59:38 GMT", 1_792_533_578),
        ("Wed, 01 Jan 2020 00:00:00 GMT", 1_577_836_800),
        ("Thu, 29 Feb 2024 12:00:00 GMT", 1_709_208_000),
        ("Fri, 31 Dec 2100 23:59:59 GMT", 4_133_980_799),
    ] {
        assert_eq!(parse_imf_fixdate(s), Some(epoch), "{s}");
    }
}

#[test]
fn rejects_impossible_calendar_dates() {
    for bad in [
        "Sat, 31 Feb 2026 10:00:00 GMT",
        "Sun, 29 Feb 2026 10:00:00 GMT", // 2026 is not a leap year
        "Sun, 29 Feb 2100 10:00:00 GMT", // 2100 is not a leap year
        "Thu, 31 Apr 2026 10:00:00 GMT",
        "Tue, 00 Oct 2026 10:00:00 GMT",
        "Sat, 32 Oct 2026 10:00:00 GMT",
        "Sat, 31 Nov 2026 10:00:00 GMT",
    ] {
        assert_eq!(parse_imf_fixdate(bad), None, "{bad}");
    }
}

#[test]
fn rejects_out_of_range_times() {
    for bad in [
        "Tue, 20 Oct 2026 24:00:00 GMT",
        "Tue, 20 Oct 2026 23:60:00 GMT",
        "Tue, 20 Oct 2026 23:59:60 GMT", // leap second is not accepted
        "Tue, 20 Oct 2026 23:59:61 GMT",
        "Tue, 20 Oct 2026 99:99:99 GMT",
    ] {
        assert_eq!(parse_imf_fixdate(bad), None, "{bad}");
    }
}

#[test]
fn weekday_must_match_the_date() {
    assert!(parse_imf_fixdate("Tue, 20 Oct 2026 21:59:38 GMT").is_some());
    for wrong in ["Mon", "Wed", "Thu", "Fri", "Sat", "Sun"] {
        let s = format!("{wrong}, 20 Oct 2026 21:59:38 GMT");
        assert_eq!(parse_imf_fixdate(&s), None, "{s}");
    }
    assert_eq!(parse_imf_fixdate("Tuesday, 20 Oct 2026 21:59:38 GMT"), None);
    assert_eq!(parse_imf_fixdate("tue, 20 Oct 2026 21:59:38 GMT"), None);
    assert_eq!(parse_imf_fixdate("Xyz, 20 Oct 2026 21:59:38 GMT"), None);
}

#[test]
fn year_must_be_2020_to_2100() {
    // Weekdays below are correct for each date, so only the range can reject them.
    for bad in [
        "Thu, 01 Jan 1970 00:00:00 GMT",
        "Tue, 31 Dec 2019 23:59:59 GMT",
        "Sat, 01 Jan 2101 00:00:00 GMT",
        "Fri, 31 Dec 9999 23:59:59 GMT",
    ] {
        assert_eq!(parse_imf_fixdate(bad), None, "{bad}");
    }
}

#[test]
fn fixed_width_fields_only() {
    for bad in [
        "Tue, 20 Oct 2026 21:59:38 GMT ",
        " Tue, 20 Oct 2026 21:59:38 GMT",
        "Tue,  20 Oct 2026 21:59:38 GMT", // two spaces
        "Tue, 20  Oct 2026 21:59:38 GMT",
        "Tue,\t20 Oct 2026 21:59:38 GMT",
        "Tue, 20 Oct 2026\t21:59:38 GMT",
        "Tue, 20 Oct 2026 21:59:38\tGMT",
        "Tue, 20 Oct 2026 21:59:38 gmt",
        "Tue, 20 Oct 2026 21:59:38 UTC",
        "Tue,20 Oct 2026 21:59:38 GMT",
        "Tue 20 Oct 2026 21:59:38 GMT",
        "Tue, 6 Oct 2026 21:59:38 GMT", // one-digit day
        "Tue, 06 Oct 26 21:59:38 GMT",  // two-digit year
        "Tue, 20 Oct 02026 21:59:38 GMT",
        "Tue, 20 Oct 2026 1:59:38 GMT",
        "Tue, 20 Oct 2026 21:9:38 GMT",
        "Tue, 20 Oct 2026 21:59:3 GMT",
        "Tue, 20 oct 2026 21:59:38 GMT",
        "Tue, 20 OCT 2026 21:59:38 GMT",
        "Tue, +1 Oct 2026 21:59:38 GMT",
        "Tue, 20 Oct 2026 +1:59:38 GMT",
        "Tue, 20 Oct 2026 21:59:38 GMT\n",
        "Tue, 20 Oct 2026 21:59:38\u{a0}GMT",
        "Tue, 20 Oct 2026 21-59-38 GMT",
        "Tuesday, 20-Oct-26 21:59:38 GMT", // obsolete RFC 850
        "Tue Oct 20 21:59:38 2026",        // obsolete asctime
        "",
    ] {
        assert_eq!(parse_imf_fixdate(bad), None, "{bad:?}");
    }
}

#[test]
fn non_ascii_never_panics() {
    for s in [
        "Tué, 20 Oct 2026 21:59:38 GMT",
        "é",
        "Tue, 20 Oct 2026 21:59:38 GMé",
        "\u{1F980}\u{1F980}\u{1F980}\u{1F980}\u{1F980}\u{1F980}\u{1F980}\u{1F980}",
    ] {
        assert_eq!(parse_imf_fixdate(s), None);
    }
}

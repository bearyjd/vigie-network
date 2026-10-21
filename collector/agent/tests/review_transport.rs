//! Security review item 11: the future TLS transport can only be built from a validated
//! `PinnedTransport` (https only, no userinfo, at least one SPKI pin).

use vigie_agent::transport::{PinError, PinnedTransport};

// base64 of 32 bytes (0..32) and of 32 x 0xff
const PIN_A: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
const PIN_B: &str = "//////////////////////////////////////////8=";
const HEX_PIN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const URL: &str = "https://vigie.example.lan:8443/v1/batch";

fn ok(url: &str, pins: &[&str]) -> PinnedTransport {
    PinnedTransport::new(url, pins).unwrap()
}

#[test]
fn accepts_a_plain_https_url_with_pins() {
    let t = ok(URL, &[PIN_A, PIN_B]);
    assert_eq!(t.host(), "vigie.example.lan");
    assert_eq!(t.port(), 8443);
    assert_eq!(t.path(), "/v1/batch");
    assert_eq!(t.pins().len(), 2);
    assert_eq!(t.pins()[0][0], 0);
    assert_eq!(t.pins()[0][31], 31);
    assert_eq!(t.pins()[1], [0xff; 32]);
}

#[test]
fn scheme_is_checked_case_insensitively_and_must_be_https() {
    assert!(PinnedTransport::new("HTTPS://h.example/x", &[PIN_A]).is_ok());
    assert!(PinnedTransport::new("HtTpS://h.example/x", &[PIN_A]).is_ok());
    for bad in [
        "http://h.example/x",
        "HTTP://h.example/x",
        "ftp://h.example/x",
        "h.example/x",
        "//h.example/x",
        "https:/h.example/x",
        "https:h.example",
        "httpss://h.example",
        " https://h.example/x",
        "",
    ] {
        assert_eq!(
            PinnedTransport::new(bad, &[PIN_A]).err(),
            Some(PinError::Scheme),
            "{bad:?}"
        );
    }
}

#[test]
fn userinfo_is_rejected_however_it_is_spelled() {
    for bad in [
        "https://user@h.example/x",
        "https://user:pw@h.example/x",
        "https://@h.example/x",
        "https://h.example@evil.example/x",
        "https://h.example%40evil.example/x",
        "https://h.example\\@evil.example/x",
        "https://evil.example\\.h.example/x",
    ] {
        assert!(PinnedTransport::new(bad, &[PIN_A]).is_err(), "{bad:?}");
    }
    assert_eq!(
        PinnedTransport::new("https://u:p@h.example/", &[PIN_A]).err(),
        Some(PinError::Userinfo)
    );
}

#[test]
fn needs_at_least_one_valid_pin() {
    assert_eq!(
        PinnedTransport::new(URL, &[] as &[&str]).err(),
        Some(PinError::NoPins)
    );
    for bad in [
        "",
        "AAAA",
        "not base64!",
        // 44 chars but 33 bytes would need different padding; one char too long
        &format!("{PIN_A}A"),
        // non-canonical trailing bits
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh9=",
        // valid base64 of 31 bytes
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHg==",
        // URL-safe alphabet is not accepted
        "__________________________________________8=",
    ] {
        assert!(
            matches!(PinnedTransport::new(URL, &[bad]), Err(PinError::BadPin(_))),
            "{bad:?}"
        );
    }
    // one good pin and one bad pin is still a refusal (a typo must not silently drop a pin)
    assert!(PinnedTransport::new(URL, &[PIN_A, "oops"]).is_err());
}

#[test]
fn the_hex_pins_of_the_config_file_are_accepted_too() {
    let t = ok(URL, &[HEX_PIN]);
    assert_eq!(t.pins()[0][0], 0x01);
    assert_eq!(t.pins()[0][1], 0x23);
}

#[test]
fn uppercase_and_mixed_case_hex_pins_are_accepted_and_equal_to_lowercase() {
    let lower = ok(URL, &[HEX_PIN]);
    for variant in [
        HEX_PIN.to_ascii_uppercase(),
        "0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
    ] {
        assert_eq!(
            ok(URL, &[variant.as_str()]).pins(),
            lower.pins(),
            "{variant}"
        );
    }
    // Still strict about everything else: non-hex and wrong lengths stay refused.
    let g = HEX_PIN.replacen('0', "G", 1);
    assert!(matches!(
        PinnedTransport::new(URL, &[g.as_str()]),
        Err(PinError::BadPin(0))
    ));
}

#[test]
fn identical_pins_are_refused_whatever_their_spelling() {
    let upper = HEX_PIN.to_ascii_uppercase();
    // PIN_A is base64 of 0..32, which is HEX_PIN's first 32 bytes only by construction below.
    let hex_a: String = (0u8..32).map(|b| format!("{b:02x}")).collect();
    for (pins, dup) in [
        (vec![PIN_A, PIN_A], 1),
        (vec![HEX_PIN, HEX_PIN], 1),
        (vec![HEX_PIN, upper.as_str()], 1),
        (vec![PIN_A, PIN_B, hex_a.as_str()], 2),
        (vec![PIN_B, PIN_A, PIN_B], 2),
    ] {
        match PinnedTransport::new(URL, &pins) {
            Err(PinError::DuplicatePin(i)) => assert_eq!(i, dup, "{pins:?}"),
            other => panic!("{pins:?}: {other:?}"),
        }
    }
    let msg = PinnedTransport::new(URL, &[PIN_A, PIN_A])
        .unwrap_err()
        .to_string();
    assert!(msg.contains("pin 2") && msg.contains("same"), "{msg}");
    // Distinct pins still work.
    assert_eq!(ok(URL, &[PIN_A, PIN_B, HEX_PIN]).pins().len(), 3);
}

#[test]
fn host_and_port_are_validated() {
    assert_eq!(ok("https://h.example/x", &[PIN_A]).port(), 443);
    assert_eq!(ok("https://[fd00::1]:9443/x", &[PIN_A]).host(), "[fd00::1]");
    assert_eq!(ok("https://h.example", &[PIN_A]).path(), "/");
    for bad in [
        "https:///x",
        "https://:443/x",
        "https://h.example:0/x",
        "https://h.example:65536/x",
        "https://h.example:port/x",
        "https://h exa.example/x",
        "https://h.example\r\n/x",
    ] {
        assert!(PinnedTransport::new(bad, &[PIN_A]).is_err(), "{bad:?}");
    }
}

#[test]
fn the_pinned_transport_does_not_implement_transport_itself() {
    // `PinnedTransport` is only validated parameters: the sole way to send is `HttpsTransport`
    // (which does SPKI-pinned TLS), reached through `transport::make`.
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/src/");
    let transport = std::fs::read_to_string(format!("{dir}transport.rs")).unwrap();
    assert!(!transport.contains("impl Transport for PinnedTransport"));
    let https = std::fs::read_to_string(format!("{dir}https.rs")).unwrap();
    assert!(https.contains("impl Transport for HttpsTransport"));
    assert_eq!(https.matches("impl Transport for").count(), 1);
}

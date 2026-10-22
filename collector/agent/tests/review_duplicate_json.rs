//! `body_says_duplicate` reads only the top-level `"duplicate"` boolean of the server reply, so a
//! nested key or a string value cannot spoof a lost-ACK duplicate.

use vigie_agent::sender::body_says_duplicate;

fn dup(s: &str) -> bool {
    body_says_duplicate(s.as_bytes())
}

#[test]
fn plain_replies() {
    assert!(dup(r#"{"duplicate":true}"#));
    assert!(!dup(r#"{"duplicate":false}"#));
    assert!(!dup("{}"));
    assert!(dup(r#"{"accepted":3,"duplicate":true,"x":null}"#));
    assert!(dup(r#"{"a":[1,2,{"duplicate":false}],"duplicate":true}"#));
}

#[test]
fn any_json_whitespace_is_fine() {
    assert!(dup("{ \"duplicate\" : true }"));
    assert!(dup("\t{\n\t\"duplicate\"\t:\r\n\ttrue\n}\n"));
    assert!(dup("{\"duplicate\":\ttrue}"));
    assert!(dup("{\"duplicate\"\n:\ntrue}"));
}

#[test]
fn nested_keys_cannot_spoof() {
    assert!(!dup(r#"{"data":{"duplicate":true}}"#));
    assert!(!dup(r#"{"data":[{"duplicate":true}]}"#));
    assert!(!dup(
        r#"{"a":{"b":{"c":{"duplicate":true}}},"duplicate":false}"#
    ));
    assert!(dup(r#"{"a":{"duplicate":false},"duplicate":true}"#));
}

#[test]
fn string_contents_cannot_spoof() {
    assert!(!dup(r#"{"msg":"\"duplicate\": true"}"#));
    assert!(!dup(r#"{"msg":"\"duplicate\":true"}"#));
    assert!(!dup(
        r#"{"msg":"x\\","duplicate":false,"n":"\"duplicate\":true"}"#
    ));
    // an escaped backslash right before the closing quote must end the string
    assert!(dup(r#"{"msg":"a\\","duplicate":true}"#));
    assert!(!dup(r#"{"duplicate":"true"}"#));
    assert!(!dup(r#"{"duplicate":1}"#));
    assert!(!dup(r#"{"duplicate":null}"#));
}

#[test]
fn escaped_key_spelling_is_still_the_same_key() {
    assert!(dup(r#"{"dup\u006cicate":true}"#));
}

#[test]
fn repeated_duplicate_key_is_refused() {
    assert!(!dup(r#"{"duplicate":true,"duplicate":false}"#));
    assert!(!dup(r#"{"duplicate":false,"duplicate":true}"#));
    assert!(!dup(r#"{"duplicate":true,"duplicate":true}"#));
}

#[test]
fn not_an_object_or_malformed_is_false() {
    for bad in [
        "",
        "true",
        r#""duplicate":true"#,
        r#"[{"duplicate":true}]"#,
        r#"[{"duplicate":true}"#,
        r#"{"duplicate":true"#,
        r#"{"duplicate":true,}"#,
        r#"{"duplicate":true} x"#,
        r#"{"duplicate":true}{"a":1}"#,
        r#"{duplicate:true}"#,
        r#"{"duplicate" true}"#,
        r#"{"duplicate":tru}"#,
        r#"{"duplicate":True}"#,
        r#"{"a":"unterminated,"duplicate":true}"#,
        "{\"duplicate\":true,\"a\":\"\u{1}\"}", // raw control character in a string
    ] {
        assert!(!dup(bad), "{bad:?}");
    }
    assert!(!body_says_duplicate(&[0xff, 0xfe, b'{']));
}

#[test]
fn deeply_nested_input_is_refused_not_a_stack_overflow() {
    let deep = format!(
        "{{\"a\":{}1{},\"duplicate\":true}}",
        "[".repeat(100_000),
        "]".repeat(100_000)
    );
    assert!(!dup(&deep));
}

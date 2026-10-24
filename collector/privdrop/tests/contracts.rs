use std::ffi::OsString;
use vigie_privdrop::{parse, verify_status};

fn input(uid: &str, gid: &str, program: &str) -> Vec<OsString> {
    [uid, gid, program, "--config", "/etc/vigie/collector.conf"]
        .into_iter()
        .map(Into::into)
        .collect()
}
fn status() -> String {
    "Uid: 20061 20061 20061 20061\nGid: 20062 20062 20062 20062\nGroups:\nNoNewPrivs: 1\nCapInh: 0000000000000000\nCapPrm: 0000000000000000\nCapEff: 0000000000000000\nCapBnd: 0000000000000000\nCapAmb: 0000000000000000\n".into()
}

#[test]
fn canonical_dedicated_ids_absolute_program_and_literal_argv_are_preserved() {
    let args = parse(input("20061", "20062", "/usr/libexec/vigie/vigie-run.sh")).unwrap();
    assert_eq!((args.uid, args.gid), (20061, 20062));
    assert_eq!(
        args.program,
        OsString::from("/usr/libexec/vigie/vigie-run.sh")
    );
    assert_eq!(
        args.args,
        [
            OsString::from("--config"),
            OsString::from("/etc/vigie/collector.conf")
        ]
    );
    assert!(parse(input("4294967294", "4294967294", "/bin/true")).is_ok());
}

#[test]
fn root_nobody_system_sentinel_alias_and_injected_ids_fail_closed() {
    for bad in [
        "0",
        "999",
        "65534",
        "065534",
        "020061",
        "+20061",
        "-1",
        "4294967295",
        "4294967296",
        "20061;id",
        "",
        " 20061",
    ] {
        assert!(
            parse(input(bad, "20062", "/bin/true")).is_err(),
            "uid {bad}"
        );
        assert!(
            parse(input("20061", bad, "/bin/true")).is_err(),
            "gid {bad}"
        );
    }
}

#[test]
fn relative_parent_missing_and_nul_programs_or_arguments_are_refused() {
    for path in [
        "true",
        "../bin/true",
        "/usr/../bin/true",
        "/tmp/./../bin/true",
        "/bin/true\0evil",
    ] {
        assert!(parse(input("20061", "20062", path)).is_err());
    }
    assert!(parse(vec![]).is_err());
    let mut args = input("20061", "20062", "/bin/true");
    args.push(OsString::from("nul\0arg"));
    assert!(parse(args).is_err());
}

#[test]
fn complete_linux_status_requires_all_four_ids_empty_groups_nnp_and_all_five_masks_zero() {
    assert!(verify_status(&status(), 20061, 20062).is_ok());
    for (old, new) in [
        ("Uid: 20061 20061 20061 20061", "Uid: 20061 20061 0 20061"),
        ("Gid: 20062 20062 20062 20062", "Gid: 20062 20062 20062 0"),
        ("Groups:", "Groups: 0"),
        ("NoNewPrivs: 1", "NoNewPrivs: 0"),
    ] {
        assert!(verify_status(&status().replace(old, new), 20061, 20062).is_err());
    }
    for key in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
        assert!(
            verify_status(
                &status().replace(
                    &format!("{key}: 0000000000000000"),
                    &format!("{key}: 0000000000000001")
                ),
                20061,
                20062
            )
            .is_err(),
            "{key}"
        );
    }
}

#[test]
fn missing_duplicate_malformed_or_oversized_status_fields_never_verify() {
    for value in [
        status().replace("CapAmb: 0000000000000000\n", ""),
        format!("{}NoNewPrivs: 1\n", status()),
        status().replace("CapEff: 0000000000000000", "CapEff: invalid"),
        status().replace("CapBnd: 0000000000000000", "CapBnd: 10000000000000000"),
        status().replace("Uid: 20061 20061 20061 20061", "Uid: 20061 20061 20061"),
    ] {
        assert!(verify_status(&value, 20061, 20062).is_err());
    }
}

#[test]
fn capability_fields_require_hex_digits_without_signed_or_oversized_aliases() {
    for alias in ["+0", "00000000000000000", "-0"] {
        assert!(
            verify_status(
                &status().replace("CapAmb: 0000000000000000", &format!("CapAmb: {alias}")),
                20061,
                20062
            )
            .is_err(),
            "{alias}"
        );
    }
}

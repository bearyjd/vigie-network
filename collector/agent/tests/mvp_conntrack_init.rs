//! Execute only a fixture copy with stubbed account/procd calls; never start a root service.
use std::fs;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};

static N: AtomicU32 = AtomicU32::new(0);

fn fixture() -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "vigie init {} {} {}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&dir).unwrap();
    dir
}

fn run_init(uid: &str, gid: &str, account_ok: bool, directory: &str) -> (Output, String) {
    let dir = fixture();
    let shared = dir.join("shared");
    if directory != "missing" {
        fs::create_dir(&shared).unwrap();
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o751)).unwrap();
    }
    if directory == "symlink" {
        fs::rename(&shared, dir.join("real")).unwrap();
        symlink(dir.join("real"), &shared).unwrap();
    }
    let source = fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/deploy/vigie-conntrack.init"
    ))
    .expect("checked-in helper init must exist");
    assert!(source.starts_with("#!/bin/sh /etc/rc.common\n"));
    // Only the shared-directory constant changes. Production has no environment path override.
    fs::write(
        dir.join("init"),
        source
            .replace("/tmp/vigie", shared.to_str().unwrap())
            .replace("/usr/libexec/vigie/vigie-logfs.sh", "\"$LOGFS_CHECK\""),
    )
    .unwrap();
    fs::write(
        dir.join("logfs-check"),
        if directory == "unmounted" {
            "#!/bin/sh\nexit 70\n"
        } else {
            "#!/bin/sh\nexit 0\n"
        },
    )
    .unwrap();
    fs::set_permissions(dir.join("logfs-check"), fs::Permissions::from_mode(0o700)).unwrap();
    let out = Command::new("sh")
        .args([
            "-c",
            r#"
        id() {
            [ "$ACCOUNT_OK" = 1 ] || return 1
            case "$*" in
                '-u vigie') printf '%s\n' "$ACCOUNT_UID" ;;
                '-g vigie') printf '%s\n' "$ACCOUNT_GID" ;;
                *) return 1 ;;
            esac
        }
        logger() { :; }
        procd_open_instance() { printf 'open\n' >> "$TRACE"; }
        procd_set_param() { printf '<%s>' "$@" >> "$TRACE"; printf '\n' >> "$TRACE"; }
        procd_close_instance() { printf 'close\n' >> "$TRACE"; }
        . "$INIT"
        start_service
    "#,
        ])
        .env("INIT", dir.join("init"))
        .env("LOGFS_CHECK", dir.join("logfs-check"))
        .env("TRACE", dir.join("trace"))
        .env("ACCOUNT_UID", uid)
        .env("ACCOUNT_GID", gid)
        .env("ACCOUNT_OK", if account_ok { "1" } else { "0" })
        .output()
        .unwrap();
    let trace = fs::read_to_string(dir.join("trace")).unwrap_or_default();
    (out, trace)
}

#[test]
fn real_account_ids_and_fixed_argv_are_passed_to_root_helper() {
    let (out, trace) = run_init("6701", "6702", true, "ready");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        trace.contains("<command></usr/bin/vigie-conntrack><--socket>"),
        "{trace}"
    );
    assert!(
        trace.contains("/shared/conntrack.sock><--uid><6701><--gid><6702><--interval><60>"),
        "{trace}"
    );
    assert!(trace.contains("<respawn><3600><5><5>"), "{trace}");
    assert!(trace.contains("<stderr><1>"), "{trace}");
    assert!(
        !trace.contains("<user>"),
        "helper must retain root for proc access: {trace}"
    );
}

#[test]
fn missing_or_unsafe_account_never_opens_a_procd_instance() {
    for (uid, gid, exists) in [
        ("6701", "6702", false),
        ("0", "6702", true),
        ("65534", "6702", true),
        ("999", "6702", true),
        ("065534", "6702", true),
        ("6701", "065534", true),
        ("", "6702", true),
        ("4294967295", "6702", true),
        ("6701", "4294967295", true),
        ("4294967296", "6702", true),
        ("6701", "4294967296", true),
        ("6701", "0", true),
        ("6701", "65534", true),
        ("6701 --allow-shared-uid", "6702", true),
        ("6701", "2;touch injected", true),
    ] {
        let (out, trace) = run_init(uid, gid, exists, "ready");
        assert!(!out.status.success(), "unsafe account {uid}:{gid} accepted");
        assert!(trace.is_empty(), "unsafe account registered {trace}");
    }
}

#[test]
fn collector_must_prepare_shared_directory_before_helper_starts() {
    for state in ["missing", "symlink", "unmounted"] {
        let (out, trace) = run_init("6701", "6702", true, state);
        assert!(!out.status.success(), "{state} shared directory accepted");
        assert!(trace.is_empty());
    }
    let dir = fixture();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o751)).unwrap();
    let uid = fs::metadata(&dir).unwrap().uid();
    vigie_conntrack::sock::check_dir_for(&dir, &[uid]).unwrap();
    assert_eq!(
        fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
        0o751
    );
}

#[test]
fn install_printer_includes_helper_lifecycle_in_correct_order() {
    let dir = fixture();
    fs::write(dir.join("passwd"), "root:x:0:0::/:/bin/sh\n").unwrap();
    fs::write(dir.join("group"), "root:x:0:\n").unwrap();
    let out = Command::new("sh")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/deploy/vigie-print-install-commands.sh"
        ))
        .env("VIGIE_TEST", "1")
        .env("VIGIE_PASSWD", dir.join("passwd"))
        .env("VIGIE_GROUP_FILE", dir.join("group"))
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("vigie-conntrack.init /etc/init.d/vigie-conntrack"));
    assert!(text.contains("/usr/bin/vigie-conntrack"));
    let collector = text.find("/etc/init.d/vigie-collector start").unwrap();
    let helper = text.find("/etc/init.d/vigie-conntrack start").unwrap();
    assert!(collector < helper);
    assert!(text.contains("# /etc/init.d/vigie-conntrack stop"));
    assert!(text.contains("# /etc/init.d/vigie-conntrack disable"));
    assert!(text.contains("# rm -f /etc/init.d/vigie-conntrack"));
}

#[test]
fn printed_account_check_aborts_before_install_for_existing_mismatched_account() {
    let dir = fixture();
    fs::write(dir.join("passwd"), "root:x:0:0::/:/bin/sh\n").unwrap();
    fs::write(dir.join("group"), "root:x:0:\n").unwrap();
    let out = Command::new("sh")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/deploy/vigie-print-install-commands.sh"
        ))
        .env("VIGIE_TEST", "1")
        .env("VIGIE_PASSWD", dir.join("passwd"))
        .env("VIGIE_GROUP_FILE", dir.join("group"))
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    let check = text
        .split("# Verify the selected account before installing files or changing key ownership.\n")
        .nth(1)
        .expect("printer must fail closed for pre-existing mismatched accounts")
        .split("# 2.")
        .next()
        .unwrap();
    fs::write(dir.join("check"), check).unwrap();
    for (uid, gid, expected) in [
        ("6700", "6700", true),
        ("6701", "6700", false),
        ("6700", "6701", false),
        ("0", "0", false),
    ] {
        let out = Command::new("sh")
            .args([
                "-c",
                r#"
            id() {
                case "$*" in
                    '-u vigie') printf '%s\n' "$FIXTURE_UID" ;;
                    '-g vigie') printf '%s\n' "$FIXTURE_GID" ;;
                    '-gn vigie') printf '%s\n' vigie ;;
                    *) return 1 ;;
                esac
            }
            . "$CHECK"
        "#,
            ])
            .env("FIXTURE_UID", uid)
            .env("FIXTURE_GID", gid)
            .env("CHECK", dir.join("check"))
            .output()
            .unwrap();
        assert_eq!(out.status.success(), expected, "account {uid}:{gid}");
    }
}

#[test]
fn printer_refuses_preexisting_group_name_and_unsafe_gid_values() {
    for (group, gid) in [
        ("root:x:0:\nvigie:x:6702:\n", "6700"),
        ("root:x:0:\n", "065534"),
        ("root:x:0:\n", "4294967295"),
    ] {
        let dir = fixture();
        fs::write(dir.join("passwd"), "root:x:0:0::/:/bin/sh\n").unwrap();
        fs::write(dir.join("group"), group).unwrap();
        let out = Command::new("sh")
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/deploy/vigie-print-install-commands.sh"
            ))
            .env("VIGIE_TEST", "1")
            .env("VIGIE_PASSWD", dir.join("passwd"))
            .env("VIGIE_GROUP_FILE", dir.join("group"))
            .env("VIGIE_UID", "6700")
            .env("VIGIE_GID", gid)
            .output()
            .unwrap();
        assert!(
            !out.status.success(),
            "unsafe group {group:?}, gid {gid} accepted"
        );
        assert!(
            out.stdout.is_empty(),
            "unsafe setup printed install commands"
        );
    }
}

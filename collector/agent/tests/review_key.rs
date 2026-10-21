//! Security review item 6: key file checks on the opened descriptor, parent directory checks,
//! no symlink following, buffers wiped.

use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use vigie_agent::config::{check_dir_meta, load_key, wipe, KeyError};

static N: AtomicU32 = AtomicU32::new(0);

fn tmpdir(mode: u32) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "vigie-key-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    fs::create_dir_all(&d).unwrap();
    fs::set_permissions(&d, fs::Permissions::from_mode(mode)).unwrap();
    d
}

fn write_key(dir: &std::path::Path) -> PathBuf {
    let k = dir.join("key");
    fs::write(&k, format!("{}\n", "cd".repeat(32))).unwrap();
    fs::set_permissions(&k, fs::Permissions::from_mode(0o600)).unwrap();
    k
}

#[test]
fn key_in_a_group_or_world_writable_directory_is_refused() {
    for mode in [0o770, 0o757, 0o777] {
        let d = tmpdir(mode);
        let k = write_key(&d);
        assert_eq!(
            load_key(&k),
            Err(KeyError::BadDirMode(mode)),
            "dir mode {mode:o}"
        );
        fs::remove_dir_all(d).unwrap();
    }
    let d = tmpdir(0o755);
    let k = write_key(&d);
    assert_eq!(load_key(&k).unwrap(), vec![0xcd; 32]);
    fs::remove_dir_all(d).unwrap();
}

#[test]
fn a_symlinked_key_is_refused_by_the_open_itself() {
    let d = tmpdir(0o755);
    let k = write_key(&d);
    let link = d.join("link");
    symlink(&k, &link).unwrap();
    // The target is a perfectly good 0600 file we own, so only O_NOFOLLOW stops this.
    assert!(matches!(
        load_key(&link),
        Err(KeyError::Io(_)) | Err(KeyError::NotRegularFile)
    ));
    fs::remove_dir_all(d).unwrap();
}

#[test]
fn a_symlinked_parent_directory_is_refused() {
    let real = tmpdir(0o755);
    write_key(&real);
    let holder = tmpdir(0o755);
    let link = holder.join("etc-vigie");
    symlink(&real, &link).unwrap();
    assert!(load_key(&link.join("key")).is_err());
    fs::remove_dir_all(real).unwrap();
    fs::remove_dir_all(holder).unwrap();
}

#[test]
fn directory_meta_rules() {
    const DIR: u32 = 0o040000;
    assert_eq!(
        check_dir_meta(DIR | 0o755, 0, 6700, true),
        Ok(()),
        "root-owned is fine"
    );
    assert_eq!(
        check_dir_meta(DIR | 0o700, 6700, 6700, true),
        Ok(()),
        "agent-owned is fine"
    );
    assert_eq!(
        check_dir_meta(DIR | 0o755, 1000, 6700, true),
        Err(KeyError::WrongDirOwner)
    );
    assert_eq!(
        check_dir_meta(DIR | 0o775, 0, 6700, true),
        Err(KeyError::BadDirMode(0o775))
    );
    assert_eq!(
        check_dir_meta(DIR | 0o757, 0, 6700, true),
        Err(KeyError::BadDirMode(0o757))
    );
    assert_eq!(
        check_dir_meta(DIR | 0o1777, 0, 6700, true),
        Err(KeyError::BadDirMode(0o1777)),
        "sticky /tmp-style dirs are not private"
    );
    assert_eq!(
        check_dir_meta(DIR | 0o755, 0, 6700, false),
        Err(KeyError::NotRegularFile)
    );
}

#[test]
fn wipe_zeroes_the_buffer() {
    let mut b = vec![0xaa_u8; 64];
    wipe(&mut b);
    assert!(b.iter().all(|&x| x == 0));
    assert_eq!(b.len(), 64, "length is kept");
}

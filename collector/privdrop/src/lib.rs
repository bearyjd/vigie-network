//! Linux64 privilege transition. Never install setuid; invoke explicitly as root.
//! Unsafe code is limited to the documented Linux libc ABI calls below.
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]
#[cfg(not(all(target_os = "linux", target_pointer_width = "64")))]
compile_error!("vigie-privdrop requires a 64-bit Linux target");
use std::ffi::{c_int, c_uint, c_ulong, OsString};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::{Component, Path};
use std::process::{Command, Stdio};

#[derive(Debug)]
pub struct Args {
    pub uid: u32,
    pub gid: u32,
    pub program: OsString,
    pub args: Vec<OsString>,
}
fn identity(value: &OsString) -> Result<u32, String> {
    let text = value.to_str().ok_or("ID is not ASCII")?;
    let n: u32 = text.parse().map_err(|_| "invalid numeric ID")?;
    if n < 1000 || n == 65534 || n == u32::MAX || n.to_string() != text {
        return Err("ID must be canonical, dedicated, >=1000 and below u32::MAX".into());
    }
    Ok(n)
}
pub fn parse(v: Vec<OsString>) -> Result<Args, String> {
    if v.len() < 3 {
        return Err("usage: vigie-privdrop UID GID /absolute/program [ARG ...]".into());
    }
    if v.iter().any(|arg| arg.as_os_str().as_bytes().contains(&0)) {
        return Err("NUL is not valid in an exec argument".into());
    }
    let p = Path::new(&v[2]);
    if !p.is_absolute() || p.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err("program must be an absolute path without parent components".into());
    }
    Ok(Args {
        uid: identity(&v[0])?,
        gid: identity(&v[1])?,
        program: v[2].clone(),
        args: v[3..].to_vec(),
    })
}
fn field<'a>(status: &'a str, key: &str) -> Result<&'a str, String> {
    let prefix = format!("{key}:");
    let values: Vec<_> = status
        .lines()
        .filter_map(|s| s.strip_prefix(&prefix))
        .collect();
    if values.len() != 1 {
        return Err(format!("missing/duplicate status field {key}"));
    }
    Ok(values[0].trim())
}
pub fn verify_status(s: &str, uid: u32, gid: u32) -> Result<(), String> {
    for (key, expected) in [("Uid", uid), ("Gid", gid)] {
        let ids: Result<Vec<u32>, _> = field(s, key)?.split_whitespace().map(str::parse).collect();
        if ids.map_err(|_| "invalid proc IDs")? != vec![expected; 4] {
            return Err(format!("{key} did not fully drop"));
        }
    }
    if !field(s, "Groups")?.is_empty() || field(s, "NoNewPrivs")? != "1" {
        return Err("supplementary groups or NoNewPrivs incorrect".into());
    }
    for key in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
        let mask = field(s, key)?;
        if mask.is_empty() || mask.len() > 16 || !mask.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("invalid cap mask syntax".into());
        }
        if u64::from_str_radix(mask, 16).map_err(|_| "invalid cap mask")? != 0 {
            return Err(format!("{key} not empty"));
        }
    }
    Ok(())
}
#[repr(C)]
struct CapHeader {
    version: u32,
    pid: c_int,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}
#[repr(C)]
struct RLimit {
    current: c_ulong,
    maximum: c_ulong,
}
// Linux libc ABI only. uid_t/gid_t are 32-bit on both supported 64-bit Linux targets.
extern "C" {
    fn getuid() -> c_uint;
    fn geteuid() -> c_uint;
    fn getgid() -> c_uint;
    fn getegid() -> c_uint;
    fn setgroups(size: usize, list: *const c_uint) -> c_int;
    fn setgid(gid: c_uint) -> c_int;
    fn setuid(uid: c_uint) -> c_int;
    fn getgroups(size: c_int, list: *mut c_uint) -> c_int;
    fn prctl(option: c_int, ...) -> c_int;
    fn capset(header: *mut CapHeader, data: *const CapData) -> c_int;
    fn setrlimit(resource: c_int, limits: *const RLimit) -> c_int;
    fn getrlimit(resource: c_int, limits: *mut RLimit) -> c_int;
    fn fcntl(fd: c_int, cmd: c_int, ...) -> c_int;
    fn umask(mask: c_uint) -> c_uint;
}
fn check(rc: c_int, operation: &str) -> Result<(), String> {
    if rc < 0 {
        Err(format!("{operation}: {}", std::io::Error::last_os_error()))
    } else {
        Ok(())
    }
}
fn require_root() -> Result<(), String> {
    // SAFETY: libc getters have no preconditions and do not mutate memory.
    if unsafe { getuid() == 0 && geteuid() == 0 } {
        Ok(())
    } else {
        Err("real and effective root required".into())
    }
}
fn ctl(option: c_int, a: c_ulong, b: c_ulong) -> Result<(), String> {
    // SAFETY: used only with integer-valued Linux prctl operations; all varargs are unsigned long.
    check(
        unsafe { prctl(option, a, b, 0 as c_ulong, 0 as c_ulong) },
        "prctl",
    )
}
fn mark_inherited_fds() -> Result<(), String> {
    for item in std::fs::read_dir("/proc/self/fd").map_err(|e| e.to_string())? {
        let entry = item.map_err(|e| e.to_string())?;
        let fd: c_int = entry
            .file_name()
            .to_str()
            .ok_or("non-ASCII fd")?
            .parse()
            .map_err(|_| "invalid fd")?;
        if fd >= 3 {
            // SAFETY: F_SETFD=2 accepts integer FD_CLOEXEC=1. Iteration directory remains open.
            check(unsafe { fcntl(fd, 2, 1 as c_int) }, "fcntl(CLOEXEC)")?;
        }
    }
    Ok(())
}
pub fn run() -> Result<(), String> {
    require_root()?;
    let args = parse(std::env::args_os().skip(1).collect())?;
    let last: u32 = std::fs::read_to_string("/proc/sys/kernel/cap_last_cap")
        .map_err(|e| e.to_string())?
        .trim()
        .parse()
        .map_err(|_| "invalid cap_last_cap")?;
    if last > 255 {
        return Err("unsupported cap_last_cap".into());
    }
    // Core limits are both zero, and cannot be raised by the unprivileged child.
    let limit = RLimit {
        current: 0,
        maximum: 0,
    };
    // SAFETY: Linux RLIMIT_CORE=4; pointers reference live repr(C) rlimit records.
    check(unsafe { setrlimit(4, &limit) }, "setrlimit(CORE)")?;
    // Do this while root: a UID transition can change /proc/self/fd accessibility.
    mark_inherited_fds()?;
    ctl(38, 1, 0)?; // PR_SET_NO_NEW_PRIVS
    ctl(8, 0, 0)?; // PR_SET_KEEPCAPS off
    ctl(47, 4, 0)?; // PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL
    for cap in 0..=last {
        ctl(24, cap as c_ulong, 0)?;
    } // PR_CAPBSET_DROP; effective privileges persist until setuid.
      // SAFETY: setgroups(0,NULL) empties supplementary groups; valid scalar IDs parsed above.
    check(unsafe { setgroups(0, std::ptr::null()) }, "setgroups")?;
    // SAFETY: canonical, non-system gid parsed above; this process still has root credentials.
    check(unsafe { setgid(args.gid) }, "setgid")?;
    // SAFETY: canonical, non-system uid parsed above; setuid atomically drops saved/root IDs.
    check(unsafe { setuid(args.uid) }, "setuid")?;
    let mut header = CapHeader {
        version: 0x2008_0522,
        pid: 0,
    };
    let data = [CapData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    // SAFETY: Linux capability v3 requires a header and exactly two repr(C) data records.
    check(
        // SAFETY: live header and two initialized v3 repr(C) records as required by Linux.
        unsafe { capset(&mut header, data.as_ptr()) },
        "capset(empty)",
    )?;
    // SAFETY: getters need no preconditions; getgroups(0,NULL) returns only the count.
    if unsafe {
        getuid() != args.uid
            || geteuid() != args.uid
            || getgid() != args.gid
            || getegid() != args.gid
            || getgroups(0, std::ptr::null_mut()) != 0
    } {
        return Err("credential verification failed".into());
    }
    let mut observed = RLimit {
        current: 1,
        maximum: 1,
    };
    // SAFETY: Linux RLIMIT_CORE=4 writes one live repr(C) rlimit record.
    check(unsafe { getrlimit(4, &mut observed) }, "getrlimit(CORE)")?;
    if observed.current != 0 || observed.maximum != 0 {
        return Err("core limit verification failed".into());
    }
    verify_status(
        &std::fs::read_to_string("/proc/self/status").map_err(|e| e.to_string())?,
        args.uid,
        args.gid,
    )?;
    // SAFETY: umask has no failure result; 077 restricts future file creation only.
    unsafe {
        umask(0o077);
    }
    let error = Command::new(&args.program)
        .args(&args.args)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .current_dir("/")
        .stdin(Stdio::null())
        .exec();
    Err(format!("exec: {error}"))
}

#[cfg(test)]
mod abi_tests {
    use super::*;
    #[test]
    fn inherited_descriptor_is_marked_close_on_exec_using_real_kernel_flags() {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::OpenOptionsExt;
        let path = std::env::temp_dir().join(format!(
            "vigie-privdrop-fd-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        let fd = file.as_raw_fd();
        // SAFETY: this live test-owned descriptor accepts F_SETFD with an integer zero mask.
        assert_eq!(unsafe { fcntl(fd, 2, 0 as c_int) }, 0);
        mark_inherited_fds().unwrap();
        // SAFETY: F_GETFD takes no additional value and inspects the same live descriptor.
        assert_eq!(unsafe { fcntl(fd, 1) } & 1, 1);
        drop(file);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn capability_and_rlimit_records_match_linux64_abi() {
        assert_eq!(std::mem::size_of::<CapHeader>(), 8);
        assert_eq!(std::mem::size_of::<CapData>(), 12);
        assert_eq!(std::mem::size_of::<RLimit>(), 16);
        assert_eq!(std::mem::size_of::<c_uint>(), 4);
        assert_eq!(std::mem::size_of::<c_ulong>(), 8);
    }
}

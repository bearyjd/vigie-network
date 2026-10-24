//! Kernel refusal test; any root test runner drops its child before executing the helper.
use std::ffi::{c_int, c_uint};
use std::os::unix::process::CommandExt;
use std::process::Command;
extern "C" {
    fn getuid() -> c_uint;
    fn setuid(uid: c_uint) -> c_int;
    fn setgid(gid: c_uint) -> c_int;
    fn setgroups(size: usize, list: *const c_uint) -> c_int;
}

#[test]
fn nonroot_caller_cannot_execute_even_a_valid_target() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_vigie-privdrop"));
    command.args(["20061", "20062", "/bin/true"]);
    // SAFETY: no-memory getter; root setup mutates only the soon-to-exec test child.
    if unsafe { getuid() } == 0 {
        // SAFETY: only async-signal-safe scalar credential calls run in this child;
        // no test bypass is exposed in the production binary or library.
        unsafe {
            command.pre_exec(|| {
                if setgroups(0, std::ptr::null()) != 0 || setgid(1000) != 0 || setuid(1000) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    let output = command.output().unwrap();
    assert_eq!(output.status.code(), Some(77));
    assert!(String::from_utf8_lossy(&output.stderr).contains("real and effective root required"));
}

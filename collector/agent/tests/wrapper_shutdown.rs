//! procd 2cfc26f8 signals only its service PID, not the collector process group.
//! Exercise real kernel signals and reaping; Python is already a repository CI prerequisite.
use std::process::Command;

#[test]
fn pid_only_stop_reaps_the_collector_without_counting_a_fatal_exit() {
    let result = Command::new("python3")
        .args(["-I", "-c", PROBE])
        .env(
            "WRAPPER",
            format!("{}/deploy/vigie-run.sh", env!("CARGO_MANIFEST_DIR")),
        )
        .output()
        .expect("Python kernel signal fixture starts");
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

const PROBE: &str = r#"
import ctypes, os, pathlib, signal, subprocess, tempfile, time

# Own/reap orphans even on the intentionally failing baseline; no fixture process leaks.
assert ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) == 0
shell = os.environ.get('VIGIE_WRAPPER_TEST_SHELL', '/bin/sh')
shell_argv = [shell, 'sh'] if pathlib.Path(shell).name == 'busybox' else [shell]

def identity(pid):
    try:
        return pathlib.Path('/proc/%d/stat' % pid).read_text().rsplit(') ', 1)[1].split()[19]
    except FileNotFoundError:
        return None

for mode, stop in [('ready', signal.SIGTERM), ('ready', signal.SIGINT),
                   ('early', signal.SIGTERM), ('early', signal.SIGINT),
                   ('forced_wait', signal.SIGTERM), ('forced_assignment', signal.SIGTERM),
                   ('forced_creation', signal.SIGTERM)] + [
                       ('natural', signal.SIGTERM)] * 16:
    with tempfile.TemporaryDirectory(prefix='vigie-wrapper-stop-') as folder:
        root = pathlib.Path(folder)
        state = root / 'state'; state.mkdir()
        ready = root / 'ready'
        recorded = root / 'recorded-child'
        observed = root / 'observed'
        collector = root / 'collector'
        collector.write_text('''#!/usr/bin/python3
import os, pathlib, signal, time
if os.environ['MODE'] in ('early', 'forced_creation'):
    pathlib.Path(os.environ['READY']).write_text(str(os.getpid()))
    time.sleep(10) # stop before the collector has installed any handlers
def stop(sig, frame):
    pathlib.Path(os.environ['OBSERVED']).write_text(str(sig))
    time.sleep(.05) # wrapper must reap despite another stop request while waiting
    os._exit(78) # intentional shutdown must never count as a config failure
signal.signal(signal.SIGTERM, stop)
pathlib.Path(os.environ['READY']).write_text(str(os.getpid()))
if os.environ['MODE'] == 'natural':
    os._exit(78) # race real completion against the manager's single-PID stop
while True: signal.pause()
''')
        collector.chmod(0o700)
        env = dict(os.environ, VIGIE_TEST='1', VIGIE_COLLECTOR_BIN=str(collector),
                   VIGIE_RUN_STATE_DIR=str(state), READY=str(ready), OBSERVED=str(observed), MODE=mode,
                   RECORDED_CHILD=str(recorded))
        wrapper_path = os.environ['WRAPPER']
        if mode.startswith('forced_'):
            source = pathlib.Path(wrapper_path).read_text()
            # Observation only: record $! before assignment to identify/reap our child.
            assert source.count('child=$!\n') == 1
            source = source.replace('child=$!\n', 'printf "%s\\n" "$!" >"$RECORDED_CHILD"\n'
                                    + ('kill -TERM "$$"\n' if mode == 'forced_assignment' else '')
                                    + 'child=$!\n')
            if mode == 'forced_wait':
                # Force the exact real-kernel signal after the branch check and BEFORE wait.
                assert '\twait "$child"\n' in source
                source = source.replace('\twait "$child"\n', '\tkill -TERM "$$"\n\twait "$child"\n', 1)
            if mode == 'forced_creation':
                assert '"$COLLECTOR" "$@" &' in source
                source = source.replace('"$COLLECTOR" "$@" &', 'kill -TERM "$$"\n"$COLLECTOR" "$@" &', 1)
            wrapper_path = str(root / 'scheduled-wrapper')
            pathlib.Path(wrapper_path).write_text(source)
        wrapper = subprocess.Popen(shell_argv + [wrapper_path], env=env,
                                   start_new_session=True, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL)
        child = None; owned = None
        try:
            deadline = time.monotonic() + 3
            marker = recorded if mode.startswith('forced_') else ready
            while (not marker.exists() or not marker.read_text()) and time.monotonic() < deadline:
                assert wrapper.poll() is None or marker.exists(), 'wrapper exited before collector readiness'
                time.sleep(.005)
            assert marker.exists(), 'collector never became ready'
            child = int(marker.read_text()); owned = identity(child)
            assert owned is not None or mode == 'natural' or mode.startswith('forced_')
            began = time.monotonic()
            if not mode.startswith('forced_'):
                os.kill(wrapper.pid, stop) # exactly procd's PID-only stop, never killpg
            if mode == 'ready':
                time.sleep(.01)
                os.kill(wrapper.pid, stop)
            code = wrapper.wait(timeout=.6 if mode.startswith('forced_') else 3)
            assert time.monotonic() - began < 3
            assert identity(child) is None, 'collector survived/orphaned or was not reaped'
            if mode == 'ready':
                assert observed.read_text() == str(signal.SIGTERM), 'collector did not receive stop'
            assert code == 128 + stop or (mode == 'natural' and code == 78), ('wrong stop result', code, stop)
            if code != 78:
                assert not (state / 'fails').exists(), 'intentional stop counted as fatal config exit'
            else:
                assert (state / 'fails').read_text() == 'x\n', 'natural fatal exit not counted once'
        finally:
            # Cleanup only our recorded live identities, including the red-run orphan.
            if child and owned is not None and identity(child) == owned:
                try: os.kill(child, signal.SIGKILL)
                except ProcessLookupError: pass
            if wrapper.poll() is None:
                wrapper.kill()
            wrapper.wait(timeout=3)
            if child:
                try: os.waitpid(child, 0)
                except ChildProcessError: pass
"#;

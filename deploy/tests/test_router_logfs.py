"""Root log-filesystem boundary through a real fixture FS and fake kernel/mount ports.

No test performs a mount, changes a service, or writes outside its private fixture.
"""

import os
import re
import shlex
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

DEPLOY = Path(__file__).resolve().parents[2] / "collector" / "agent" / "deploy"


class World:
    def __init__(self, root):
        self.root = Path(root)
        self.log = self.root / "vigie"
        self.info = self.root / "mountinfo"
        self.info.write_text("")
        self.calls = self.root / "calls"
        self.lock = self.root / "lock"
        self.statfs = self.root / "statfs"
        self.mount = self.root / "mount"
        self.write_script(self.statfs, "printf '4096 5120\\n'")
        self.write_script(
            self.mount,
            "printf '%s\\n' \"$@\" >> "
            + shlex.quote(str(self.calls))
            + "\nprintf '%s\\n' "
            + shlex.quote(self.mount_line())
            + " > "
            + shlex.quote(str(self.info)),
        )
        self.env = dict(
            os.environ,
            VIGIE_TEST="1",
            VIGIE_TRUSTED_UID=str(os.getuid()),
            VIGIE_OWNER=f"{os.getuid()}:{os.getgid()}",
            VIGIE_LOG_ALLOWED_UIDS=str(os.getuid()),
            VIGIE_LOGFS_DIR=str(self.log),
            VIGIE_LOGFS_MOUNTINFO=str(self.info),
            VIGIE_LOGFS_STATFS_BIN=str(self.statfs),
            VIGIE_LOGFS_MOUNT_BIN=str(self.mount),
            VIGIE_LOGFS_LOCK_DIR=str(self.lock),
            VIGIE_LOG_DIR=str(self.log),
            VIGIE_LOG_FILE=str(self.log / "dnsmasq.log"),
            VIGIE_DROPIN_DIR=str(self.root / "dnsmasq.d"),
            VIGIE_RELOAD_CMD="exit 37",
            VIGIE_WAIT_SECS="0",
        )

    @staticmethod
    def write_script(path, body):
        path.write_text("#!/bin/sh\nset -eu\n" + body + "\n")
        path.chmod(0o700)

    def mount_line(self, **changes):
        values = {
            "target": str(self.log),
            "flags": "rw,nosuid,nodev,noexec,relatime",
            "root": "/",
            "filesystem": "tmpfs",
            "source": "vigie-logfs",
            "super": "rw,size=20480k,mode=751",
        }
        values.update(changes)
        return f"20 1 0:42 {values['root']} {values['target']} {values['flags']} - {values['filesystem']} {values['source']} {values['super']}"

    def premount(self):
        self.log.mkdir(exist_ok=True)
        self.log.chmod(0o751)
        self.info.write_text(self.mount_line() + "\n")

    def run(self, action="check", script="vigie-logfs.sh"):
        return subprocess.run(
            ["sh", str(DEPLOY / script)] + ([] if action is None else [action]),
            env=self.env,
            capture_output=True,
            check=False,
            timeout=5,
        )


class LogfsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.w = World(self.tmp.name)

    def test_prepare_absent_directory_mounts_exact_cap_and_is_idempotent(self):
        result = self.w.run("prepare")
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(stat.S_IMODE(self.w.log.stat().st_mode), 0o751)
        self.assertEqual(self.w.run().returncode, 0)
        calls = self.w.calls.read_text().splitlines()
        self.assertEqual(calls[0:2], ["-t", "tmpfs"])
        self.assertIn("size=20971520", calls[3])
        self.assertIn("noexec", calls[3])
        self.assertIn("nosuid", calls[3])
        self.assertIn("nodev", calls[3])
        self.assertEqual(calls[-2:], ["vigie-logfs", str(self.w.log)])
        self.assertEqual(self.w.run("prepare").returncode, 0)
        self.assertEqual(self.w.calls.read_text().splitlines(), calls)

    def test_missing_mount_cannot_create_log_or_dropin(self):
        for script in ["vigie-dnsmasq-dropin.sh", "vigie-log-watchdog.sh"]:
            with self.subTest(script=script):
                self.assertNotEqual(self.w.run("ensure", script).returncode, 0)
        self.assertFalse(self.w.log.exists())
        self.assertFalse((self.w.root / "dnsmasq.d").exists())

    def test_empty_preexisting_owned_directory_is_accepted_but_contents_never_covered(
        self,
    ):
        self.w.log.mkdir()
        self.w.log.chmod(0o751)
        (self.w.log / "foreign").write_text("retain")
        self.assertNotEqual(self.w.run("prepare").returncode, 0)
        self.assertEqual((self.w.log / "foreign").read_text(), "retain")
        self.assertFalse(self.w.calls.exists())
        (self.w.log / "foreign").unlink()
        self.assertEqual(self.w.run("prepare").returncode, 0)

    def test_symlink_or_bad_mode_refused_without_repair(self):
        target = self.w.root / "target"
        target.mkdir()
        (target / "keep").write_text("retain")
        self.w.log.symlink_to(target)
        self.assertNotEqual(self.w.run("prepare").returncode, 0)
        self.assertEqual((target / "keep").read_text(), "retain")
        self.w.log.unlink()
        self.w.log.mkdir()
        self.w.log.chmod(0o777)
        self.assertNotEqual(self.w.run("prepare").returncode, 0)
        self.assertEqual(stat.S_IMODE(self.w.log.stat().st_mode), 0o777)

    def test_foreign_wrongsize_or_missing_flags_fail_check_and_prepare_without_mount(
        self,
    ):
        self.w.premount()
        for change in [
            {"source": "foreign"},
            {"filesystem": "ext4"},
            {"root": "/subdir"},
            {"flags": "rw,nosuid,nodev"},
            {"flags": "rw,nosuid,noexec"},
            {"flags": "rw,nodev,noexec"},
            {"super": "rw,size=16384k"},
        ]:
            self.w.info.write_text(self.w.mount_line(**change) + "\n")
            with self.subTest(change=change):
                self.assertNotEqual(self.w.run().returncode, 0)
                self.assertNotEqual(self.w.run("prepare").returncode, 0)
                self.assertFalse(self.w.calls.exists())

    def test_stacked_or_child_mounts_are_refused(self):
        self.w.premount()
        for extra in [
            self.w.mount_line(),
            self.w.mount_line(target=str(self.w.log / "child")),
        ]:
            self.w.info.write_text(self.w.mount_line() + "\n" + extra + "\n")
            self.assertNotEqual(self.w.run().returncode, 0)
            self.assertNotEqual(self.w.run("prepare").returncode, 0)
            self.assertFalse(self.w.calls.exists())

    def test_kernel_capacity_and_permissions_are_verified_independently(self):
        self.w.premount()
        self.w.write_script(self.w.statfs, "printf '4096 100000\\n'")
        self.assertNotEqual(self.w.run().returncode, 0)
        self.w.write_script(self.w.statfs, "printf '4096 5120\\n'")
        self.w.log.chmod(0o755)
        self.assertNotEqual(self.w.run().returncode, 0)
        self.w.log.chmod(0o751)
        self.assertEqual(self.w.run().returncode, 0)

    def test_prepare_only_populates_boot_config_without_reloading_dns_or_confirming_apply(
        self,
    ):
        self.w.premount()
        result = self.w.run("prepare", "vigie-dnsmasq-dropin.sh")
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(
            (self.w.root / "dnsmasq.d/vigie.conf").read_text(),
            f"log-queries=extra\nlog-dhcp\nlog-facility={self.w.log}/dnsmasq.log\n",
        )
        self.assertEqual(
            stat.S_IMODE((self.w.log / "dnsmasq.log").stat().st_mode), 0o640
        )
        self.assertFalse((self.w.log / ".dnsmasq-applied").exists())
        self.assertNotEqual(
            self.w.run("check", "vigie-dnsmasq-dropin.sh").returncode, 0
        )
        self.assertEqual(self.w.run("ensure", "vigie-dnsmasq-dropin.sh").returncode, 37)

    def test_boot_helper_prepares_mount_and_config_without_dns_reload(self):
        result = self.w.run(None, script="vigie-logfs-boot.sh")
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(self.w.run().returncode, 0)
        self.assertTrue((self.w.root / "dnsmasq.d/vigie.conf").exists())
        self.assertFalse((self.w.log / ".dnsmasq-applied").exists())
        self.assertEqual(
            re.search(
                r"^START=(\d+)$",
                (DEPLOY / "vigie-logfs.init").read_text(),
                re.MULTILINE,
            ).group(1),
            "17",
        )

    def test_leaf_symlink_is_reached_after_valid_mount_gate_and_preserves_victim(self):
        self.w.premount()
        victim = self.w.root / "victim"
        victim.write_text("retain")
        (self.w.log / "dnsmasq.log").symlink_to(victim)
        result = self.w.run("prepare", "vigie-dnsmasq-dropin.sh")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"symlink", result.stderr)
        self.assertEqual(victim.read_text(), "retain")

    def test_collector_init_gates_all_work_and_sets_explicit_group_and_core_limits(
        self,
    ):
        trace = self.w.root / "trace"
        source = (DEPLOY / "vigie-collector.init").read_text()
        for name in ("vigie-logfs.sh", "vigie-state-dir.sh", "vigie-dnsmasq-dropin.sh"):
            helper = self.w.root / name
            self.w.write_script(helper, f"echo '{name}' >> {shlex.quote(str(trace))}")
            source = source.replace(
                "/usr/libexec/vigie/" + name, shlex.quote(str(helper))
            )
        init = self.w.root / "collector.init"
        init.write_text(source)
        program = '. "$1"; id() { return 0; }; logger() { :; }; procd_open_instance() { echo OPEN >> "$TRACE"; }; procd_set_param() { printf \'[%s]\' "$@" >> "$TRACE"; printf \'\\n\' >> "$TRACE"; }; procd_close_instance() { :; }; start_service'
        result = subprocess.run(
            ["sh", "-c", program, "fixture", str(init)],
            env=dict(self.w.env, TRACE=str(trace)),
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        text = trace.read_text()
        self.assertEqual(
            text.splitlines()[:4],
            ["vigie-logfs.sh", "vigie-state-dir.sh", "vigie-dnsmasq-dropin.sh", "OPEN"],
        )
        self.assertIn("[user][vigie]", text)
        self.assertIn("[group][vigie]", text)
        self.assertIn("[limits][core=0 0]", text)
        trace.unlink()
        self.w.write_script(
            self.w.root / "vigie-logfs.sh",
            f"echo 'blocked' >> {shlex.quote(str(trace))}\nexit 70",
        )
        result = subprocess.run(
            ["sh", "-c", program, "fixture", str(init)],
            env=dict(self.w.env, TRACE=str(trace)),
            capture_output=True,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(trace.read_text(), "blocked\n")

    def test_kernel_lock_releases_after_its_holder_dies(self):
        import select

        self.w.lock.mkdir(mode=0o700)
        lock = self.w.lock / "prepare.lock"
        lock.write_text("")
        lock.chmod(0o600)
        code = "import fcntl,sys,time; f=open(sys.argv[1],'r+'); fcntl.flock(f,fcntl.LOCK_EX); print('ready',flush=True); time.sleep(30)"
        child = subprocess.Popen(
            [sys.executable, "-c", code, str(lock)], stdout=subprocess.PIPE
        )
        try:
            self.assertTrue(
                select.select([child.stdout], [], [], 3)[0],
                "lock holder failed to initialize",
            )
            self.assertEqual(child.stdout.readline(), b"ready\n")
            self.assertNotEqual(self.w.run("prepare").returncode, 0)
            self.assertFalse(self.w.calls.exists())
        finally:
            child.kill()
            child.wait(timeout=3)
            child.stdout.close()
        self.assertEqual(self.w.run("prepare").returncode, 0)

    def test_untrusted_backing_owner_is_reached_after_trusted_lock_geometry(self):
        self.w.log.mkdir(mode=0o751)
        self.w.log.chmod(0o751)
        bin_dir = self.w.root / "bin"
        bin_dir.mkdir()
        import shutil

        real_stat = shutil.which("stat")
        body = f"if [ \"$1:$2:$3\" = '-c:%u:%g:%a:{self.w.log}' ]; then echo '{os.getuid() + 1}:{os.getgid()}:751'; else exec {shlex.quote(real_stat)} \"$@\"; fi"
        self.w.write_script(bin_dir / "stat", body)
        self.w.env["PATH"] = str(bin_dir) + ":" + os.environ["PATH"]
        result = self.w.run("prepare")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"unsafe backing", result.stderr)
        self.assertFalse(self.w.calls.exists())

    def test_lock_symlink_or_untrusted_parent_is_not_followed(self):
        self.w.lock.mkdir()
        self.w.lock.chmod(0o700)
        victim = self.w.root / "victim"
        victim.write_text("retain")
        (self.w.lock / "prepare.lock").symlink_to(victim)
        self.assertNotEqual(self.w.run("prepare").returncode, 0)
        self.assertEqual(victim.read_text(), "retain")
        (self.w.lock / "prepare.lock").unlink()
        self.w.lock.chmod(0o777)
        self.assertNotEqual(self.w.run("prepare").returncode, 0)
        self.assertFalse(self.w.calls.exists())


if __name__ == "__main__":
    unittest.main()

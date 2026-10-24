"""Static consistency checks for deploy/, README.md and docs/deploy.md.

    python3 -I deploy/tests/check_refs.py            # from the repository root
    python3 -I deploy/tests/check_refs.py --release  # also fail on unpinned base images

Checks: YAML parses; the volume mount matrix in compose.yaml equals the table in docs/deploy.md and
matches the PRP ownership rules (ingest: no overrides; api: no raw); api has its own TLS secrets;
`podman-compose config` (when installed, run against a STUB podman) accepts compose.yaml and rejects
it without VIGIE_LAN_ADDR; every VIGIE_* setting in .env.example/compose.yaml exists in server/src;
every file path cited in the docs exists (or exists on the named other branch); every `--flag` cited
in the docs is defined in server/src or deploy/ or is on the explicit list of third-party flags.
A self-test first feeds the checks bogus input and fails when any of them does not notice.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
DOCS = [ROOT / "README.md", ROOT / "docs" / "deploy.md"]
# Files that live only on other branches (this branch has no collector/ tree).
OTHER_BRANCH = {
    "collector/agent/deploy": "feat/collector",
    "collector/agent/deploy/vigie-print-install-commands.sh": "feat/collector",
    "docs/spikes/p2-collector-agent.md": "feat/collector",
    "docs/spikes/conntrack-helper.md": "feat/conntrack-helper",
    "docs/spikes/p1-collector-net.md": "spike/p1-collector-net",
}
# Flags that belong to curl, podman, scp, cargo, openssl, iptables, git, sqlite... not to Vigie.
THIRD_PARTY_FLAGS = {
    "--cacert", "--format", "--release", "--target", "--permanent", "--add-rich-rule", "--dport",
    "--to-destination", "--rm", "--no-deps", "--env-file", "--force-recreate", "--out-file",
    "--test", "--check", "--config", "--sport", "--once", "--file", "--secret",
    "--now", "--reload", "--restart", "--user", "--remove-rich-rule", "--list-rich-rules",
}
# Generated locally by the quick start, never committed (deploy/.gitignore).
GENERATED = {"deploy/.env", "deploy/certs/server.crt", "deploy/certs-api/server.crt"}
# PRP section 5 ownership: (service, volume) -> allowed modes. Anything not listed must be absent.
EXPECTED_MOUNTS = {
    "ingest": {"vigie-raw": "rw", "vigie-inv": "rw"},
    "pipeline": {"vigie-raw": "ro", "vigie-inv": "rw", "vigie-overrides": "ro"},
    "api": {"vigie-inv": "ro", "vigie-overrides": "rw"},
}
VOLUMES = ("vigie-raw", "vigie-inv", "vigie-overrides")
errors: list[str] = []


quiet = False


def err(msg: str) -> None:
    errors.append(msg)
    if not quiet:
        print(f"FAIL: {msg}", file=sys.stderr)


def source_text(*dirs: str) -> str:
    chunks = []
    for d in dirs:
        for p in (ROOT / d).rglob("*"):
            if p.is_file() and p.suffix in {".py", ".sh", ".yaml", ".example", ""} and ".venv" not in p.parts:
                try:
                    chunks.append(p.read_text(errors="ignore"))
                except OSError:
                    pass
    return "\n".join(chunks)


def mounts_of(doc: dict) -> dict[str, dict[str, str]]:
    """service -> {volume: mode} from compose `volumes:` entries like `vigie-raw:/raw:ro`."""
    result: dict[str, dict[str, str]] = {}
    for svc, cfg in doc["services"].items():
        result[svc] = {}
        for entry in cfg.get("volumes", []):
            name, _path, *mode = str(entry).split(":")
            result[svc][name] = mode[0] if mode else "rw"
    return result


def docs_matrix(text: str) -> dict[str, dict[str, str]]:
    """Parse the `| `vigie-raw` | rw | ro | - |` rows (ingest, pipeline, api columns)."""
    matrix: dict[str, dict[str, str]] = {"ingest": {}, "pipeline": {}, "api": {}}
    for line in text.splitlines():
        cells = [c.strip().strip("`") for c in line.strip().strip("|").split("|")]
        if len(cells) == 4 and cells[0] in VOLUMES:
            for svc, mode in zip(("ingest", "pipeline", "api"), cells[1:], strict=True):
                if mode in ("rw", "ro"):
                    matrix[svc][cells[0]] = mode
    return matrix


def docs_table_for(doc: dict) -> str:
    """The docs table a compose file would need (used by the self-test to isolate each check)."""
    actual = mounts_of(doc)
    rows = [
        "| " + vol + " | " + " | ".join(actual[svc].get(vol, "-") for svc in ("ingest", "pipeline", "api")) + " |"
        for vol in VOLUMES
    ]
    return "\n".join(rows)


def check_mounts(doc: dict, deploy_md: str) -> None:
    actual = mounts_of(doc)
    if actual != EXPECTED_MOUNTS:
        err(f"compose.yaml mounts {actual} differ from the PRP section 5 matrix {EXPECTED_MOUNTS}")
    if docs_matrix(deploy_md) != actual:
        err(f"docs/deploy.md mount table {docs_matrix(deploy_md)} does not match compose {actual}")


def check_services(doc: dict) -> None:
    services = set(doc["services"])
    if services != {"ingest", "pipeline", "api"}:
        err(f"unexpected services: {services}")
    for svc, cfg in doc["services"].items():
        if cfg.get("read_only") is not True:
            err(f"{svc}: read_only is not true")
        if cfg.get("cap_drop") != ["ALL"]:
            err(f"{svc}: cap_drop is not [ALL]")
        if "no-new-privileges:true" not in cfg.get("security_opt", []):
            err(f"{svc}: no-new-privileges missing")
        if not any(str(t).startswith("/tmp") for t in cfg.get("tmpfs", [])):
            err(f"{svc}: /tmp tmpfs missing")
        if not cfg.get("healthcheck"):
            err(f"{svc}: no healthcheck")
        if cfg.get("user") != "10001:10001":
            err(f"{svc}: user is not set to 10001:10001")
        if not cfg.get("mem_limit") or not cfg.get("cpus"):
            err(f"{svc}: memory/cpu limits missing")
        if "LINK_OVERRIDES" in str(cfg.get("environment")):
            err(f"{svc}: still uses the removed overrides symlink")
    for svc in ("api", "pipeline"):
        env = doc["services"][svc]["environment"]
        if env.get("VIGIE_OVERRIDES_PATH") != "/overrides/overrides.db":
            err(f"{svc}: VIGIE_OVERRIDES_PATH is not /overrides/overrides.db")
        if str(env.get("VIGIE_GUARD_OVERRIDES")) != "1":
            err(f"{svc}: VIGIE_GUARD_OVERRIDES is not 1")
    if "VIGIE_OVERRIDES_PATH" in doc["services"]["ingest"]["environment"]:
        err("ingest is given VIGIE_OVERRIDES_PATH")
    for svc in ("ingest", "api"):
        for port in doc["services"][svc]["ports"]:
            if not str(port).startswith("${VIGIE_LAN_ADDR:?"):
                err(f"{svc}: port {port} does not use the required LAN address variable")
    used = {
        svc: {str(x["source"]) for x in doc["services"][svc].get("secrets", [])}
        for svc in ("ingest", "api")
    }
    if {"vigie_api_tls_cert", "vigie_api_tls_key"} - used["api"]:
        err("api does not use its own TLS secrets vigie_api_tls_cert/key")
    if used["api"] & used["ingest"]:
        err(f"api and ingest share secrets: {used['api'] & used['ingest']}")
    if any(not s.startswith("collector_key_") and "api" in s for s in used["ingest"]):
        err("ingest mounts an api secret")


def check_yaml() -> None:
    try:
        doc = yaml.safe_load((ROOT / "deploy" / "compose.yaml").read_text())
    except yaml.YAMLError as exc:
        err(f"compose.yaml does not parse: {exc}")
        return
    check_services(doc)
    check_mounts(doc, (ROOT / "docs" / "deploy.md").read_text())
    print("yaml: ok")


PINNED = re.compile(r"^ARG (PYTHON|UV)_IMAGE=\S+@sha256:[0-9a-f]{64}$", re.M)


def check_images(containerfile: str, release: bool) -> None:
    """Base images are pinned by digest. A dev build may carry a `# TODO pin digest`; --release
    refuses anything unpinned."""
    if release and len(PINNED.findall(containerfile)) != 2:
        err("Containerfile: PYTHON_IMAGE and UV_IMAGE must both be pinned by @sha256 digest")


def check_compose_config() -> None:
    tool = shutil.which("podman-compose")
    if not tool:
        print("podman-compose not installed: skipped")
        return
    with tempfile.TemporaryDirectory() as tmp:
        # podman-compose may call `podman`: give it a stub (version queries only) so that this
        # check can never reach a real podman, directly or through distrobox-host-exec.
        stub_dir = Path(tmp) / "stubbin"
        stub_dir.mkdir()
        stub = stub_dir / "podman"
        stub.write_text('#!/bin/sh\ncase "$1" in --version|version) echo "podman version 5.0.0";; *) exit 1;; esac\n')
        stub.chmod(0o755)
        os.environ["PATH"] = f"{stub_dir}{os.pathsep}{os.environ['PATH']}"
        envfile = Path(tmp) / "env"
        envfile.write_text((ROOT / "deploy" / ".env.example").read_text())
        base = [tool, "--env-file", str(envfile), "-f", str(ROOT / "deploy" / "compose.yaml")]
        setting = "VIGIE_MONITORING_LARGE_UPLOAD_BYTES"
        clean_env = {k: v for k, v in os.environ.items() if k != setting}
        for expected, config_env in (("1073741824", clean_env),
                                     ("2097152", {**clean_env, setting: "2097152"})):
            ok = subprocess.run([*base, "config"], capture_output=True, text=True,
                                env=config_env, check=False)
            if ok.returncode != 0:
                err(f"podman-compose config failed: {ok.stderr[-300:]}")
                continue
            rendered = yaml.safe_load(ok.stdout)
            for role in ("ingest", "pipeline", "api"):
                actual = rendered["services"][role]["environment"].get(setting)
                if role == "pipeline" and str(actual) != expected:
                    err(f"rendered pipeline monitoring threshold differs from {expected}")
                elif role != "pipeline" and actual is not None:
                    err(f"rendered {role} unexpectedly receives monitoring threshold")
        env = {k: v for k, v in os.environ.items() if k != "VIGIE_LAN_ADDR"}
        bare = Path(tmp) / "empty"
        bare.write_text("")
        res = subprocess.run(
            [tool, "--env-file", str(bare), "-f", str(ROOT / "deploy" / "compose.yaml"), "config"],
            capture_output=True, text=True, env=env, check=False,
        )
        if res.returncode == 0:
            err("compose accepted an unset VIGIE_LAN_ADDR (would publish on every interface)")
    print("podman-compose config: ok")


def check_monitoring_config(doc: dict, example: str) -> None:
    setting = "VIGIE_MONITORING_LARGE_UPLOAD_BYTES"
    expected = "${VIGIE_MONITORING_LARGE_UPLOAD_BYTES:-1073741824}"
    if not re.search(r"(?m)^VIGIE_MONITORING_LARGE_UPLOAD_BYTES=1073741824(?:\s|$)", example):
        err("monitoring upload default must be documented as 1073741824 bytes")
    if doc["services"]["pipeline"]["environment"].get(setting) != expected:
        err("pipeline must forward the configurable monitoring upload threshold with its default")
    for service in ("ingest", "api"):
        if setting in doc["services"][service]["environment"]:
            err(f"monitoring upload threshold belongs only to pipeline, not {service}")


def check_env_names() -> None:
    src = set(re.findall(r"VIGIE_[A-Z0-9_]+", source_text("server/src")))
    deploy_only = {  # consumed by deploy/ scripts and compose, not by the Python services
        "VIGIE_LAN_ADDR", "VIGIE_INGEST_PORT", "VIGIE_API_PORT", "VIGIE_IMAGE_TAG",
        "VIGIE_PIPELINE_INTERVAL_S", "VIGIE_GUARD_OVERRIDES",
        "VIGIE_CERT_SAN", "VIGIE_CERT_DAYS", "VIGIE_ADMIN_CMD", "VIGIE_PIN_HEX1", "VIGIE_PIN_HEX2",
        "VIGIE_SERVER_URL", "VIGIE_COMPOSE_FILE",
    }
    for name in ("deploy/.env.example", "deploy/compose.yaml"):
        text = (ROOT / name).read_text()
        for var in sorted(set(re.findall(r"VIGIE_[A-Z0-9_]+", text))):
            if var not in src and var not in deploy_only:
                err(f"{name}: {var} is not read anywhere in server/src or deploy scripts")
    # every setting the Python services read should be documented in .env.example
    documented = set(re.findall(r"VIGIE_[A-Z0-9_]+", (ROOT / "deploy/.env.example").read_text()))
    for var in sorted(src - documented):
        if var not in {"VIGIE_DATA_DIR", "VIGIE_SECRETS_DIR", "VIGIE_TLS_CERT", "VIGIE_TLS_KEY",
                       "VIGIE_INSECURE_DEV", "VIGIE_TEST"}:
            err(f"server/src reads {var} but .env.example does not document it")
    check_monitoring_config(yaml.safe_load((ROOT / "deploy/compose.yaml").read_text()),
                            (ROOT / "deploy/.env.example").read_text())
    print("env names: ok")


def path_exists(path: str) -> bool:
    clean = path.rstrip("/")
    if (ROOT / clean).exists() or clean in GENERATED:
        return True
    ref = subprocess.run(["git", "rev-parse", "--verify", "--quiet", clean], cwd=ROOT, check=False,
                         capture_output=True)
    if ref.returncode == 0:  # a branch name such as docs/prp-rev3, not a file
        return True
    branch = OTHER_BRANCH.get(clean)
    if branch is None:
        return False
    res = subprocess.run(["git", "cat-file", "-e", f"{branch}:{clean}"], cwd=ROOT, check=False,
                         capture_output=True)
    return res.returncode == 0


def check_paths_in(name: str, text: str, base: Path | None = None) -> None:
    pat = re.compile(r"`((?:deploy|server|docs|api|collector|tests|tools)/[A-Za-z0-9_./-]+)`")
    link = re.compile(r"\]\(([A-Za-z0-9_./-]+\.(?:md|yaml|json))\)")
    for target in link.findall(text):
        resolved = ((base or ROOT) / target).resolve()
        if not resolved.exists():
            err(f"{name}: link target {target} does not exist")
    for path in sorted(set(pat.findall(text))):
        if "<" in path or path.endswith("-") or "*" in path:
            continue
        if not path_exists(path):
            err(f"{name}: cited path {path} does not exist (here or on its branch)")


def check_paths() -> None:
    for doc in DOCS:
        check_paths_in(doc.name, doc.read_text(), doc.parent)
    print("paths: ok")


def check_flags_in(name: str, text: str, known: str) -> None:
    for flag in sorted(set(re.findall(r"(?<![\w-])(--[a-z][a-z0-9-]+)", text))):
        if flag in THIRD_PARTY_FLAGS:
            continue
        if flag not in known:
            err(f"{name}: flag {flag} is not defined in server/src or deploy/")


def check_flags() -> None:
    known = source_text("server/src", "deploy") + (ROOT / "deploy/compose.yaml").read_text()
    # Flags of the router-side helper, which lives on another branch: verify them there.
    helper = subprocess.run(
        ["git", "show", "feat/conntrack-helper:collector/conntrack-helper/src/cli.rs"],
        cwd=ROOT, check=False, capture_output=True, text=True,
    ).stdout
    for doc in DOCS:
        check_flags_in(doc.name, doc.read_text(), known + helper)
    print("flags: ok")


def check_firewall(readme: str) -> None:
    """The README firewalld recipe must explicitly reject other sources on BOTH published ports,
    reload, say how to undo it and how to verify it."""
    for port in ("8443", "8444"):
        accept = rf'source address="[^"]+" port port="{port}" protocol="tcp" accept'
        reject = rf'source not address="[^"]+" port port="{port}" protocol="tcp" reject'
        if not re.search(accept, readme) or not re.search(reject, readme):
            err(f"README: firewalld recipe lacks accept + 'source not address' reject for {port}")
    for needle in ("firewall-cmd --reload", "--remove-rich-rule", "nc -vz"):
        if needle not in readme:
            err(f"README: firewalld recipe lacks {needle}")


BOGUS_PATH_DOC = "See `deploy/does-not-exist.sh` and `docs/nope.md`."
BOGUS_FLAG_DOC = "Run it with --definitely-not-a-flag now."


def _fails(label: str, fn, *args) -> None:
    """The check `fn` must report at least one problem for this deliberately bad input."""
    global quiet
    saved, quiet = errors[:], True
    errors.clear()
    try:
        fn(*args)
        caught = bool(errors)
    finally:
        errors[:] = saved
        quiet = False
    if not caught:
        err(f"self-test: {label} was not detected (the check is disabled or too weak)")


def self_test() -> None:
    good = yaml.safe_load((ROOT / "deploy" / "compose.yaml").read_text())
    deploy_md = (ROOT / "docs" / "deploy.md").read_text()
    wrong_mount = yaml.safe_load((ROOT / "deploy" / "compose.yaml").read_text())
    wrong_mount["services"]["api"]["volumes"] = ["vigie-inv:/inv:rw", "vigie-overrides:/overrides:rw"]
    ingest_sees_overrides = yaml.safe_load((ROOT / "deploy" / "compose.yaml").read_text())
    ingest_sees_overrides["services"]["ingest"]["volumes"].append("vigie-overrides:/overrides:rw")
    shared_cert = yaml.safe_load((ROOT / "deploy" / "compose.yaml").read_text())
    shared_cert["services"]["api"]["secrets"] = [{"source": "vigie_tls_cert"}, {"source": "vigie_tls_key"}]
    readme = (ROOT / "README.md").read_text()
    _fails("firewalld recipe without explicit reject", check_firewall, readme.replace(" reject'", " accept'"))
    _fails("firewalld recipe without the 8444 rule", check_firewall, readme.replace('port="8444"', 'port="9"'))
    _fails("a path that does not exist", check_paths_in, "bogus.md", BOGUS_PATH_DOC)
    _fails("a flag nobody defines", check_flags_in, "bogus.md", BOGUS_FLAG_DOC, "--real-flag")
    # the docs table is made to AGREE with the bad compose, so only the PRP-matrix check can fire
    _fails("api inventory mounted rw", check_mounts, wrong_mount, docs_table_for(wrong_mount))
    _fails("ingest mounting overrides", check_mounts, ingest_sees_overrides, docs_table_for(ingest_sees_overrides))
    _fails("docs table out of step with compose", check_mounts, good, deploy_md.replace("| rw |", "| ro |"))
    _fails("api sharing ingest's TLS secrets", check_services, shared_cert)
    _fails("an unpinned base image under --release", check_images, "ARG PYTHON_IMAGE=python:3.12\nARG UV_IMAGE=uv:1", True)
    setting = "VIGIE_MONITORING_LARGE_UPLOAD_BYTES"
    contract = {"services": {svc: {"environment": {}} for svc in ("pipeline", "ingest", "api")}}
    contract["services"]["pipeline"]["environment"][setting] = "${VIGIE_MONITORING_LARGE_UPLOAD_BYTES:-1073741824}"
    example = "VIGIE_MONITORING_LARGE_UPLOAD_BYTES=1073741824\n"
    check_monitoring_config(contract, example)
    _fails("missing monitoring default documentation", check_monitoring_config, contract, "")
    _fails("incorrect monitoring default documentation", check_monitoring_config, contract, example.replace("1073741824", "1"))
    contract["services"]["api"]["environment"][setting] = "1"
    _fails("monitoring setting forwarded to wrong role", check_monitoring_config, contract, example)
    del contract["services"]["api"]["environment"][setting]
    del contract["services"]["pipeline"]["environment"][setting]
    _fails("monitoring threshold not forwarded", check_monitoring_config, contract, example)
    # and the checks accept the real inputs
    check_mounts(good, deploy_md)
    check_firewall(readme)
    check_images((ROOT / "deploy" / "Containerfile").read_text(), True)


def main() -> int:
    release = "--release" in sys.argv[1:]
    self_test()
    check_yaml()
    check_images((ROOT / "deploy" / "Containerfile").read_text(), release)
    check_firewall((ROOT / "README.md").read_text())
    check_compose_config()
    check_env_names()
    check_paths()
    check_flags()
    if errors:
        print(f"{len(errors)} problem(s)", file=sys.stderr)
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

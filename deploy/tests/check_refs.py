"""Static consistency checks for deploy/, README.md and docs/deploy.md.

    python3 -I deploy/tests/check_refs.py            # from the repository root

Checks: YAML parses; `podman-compose config` (when installed) accepts compose.yaml and rejects it
without VIGIE_LAN_ADDR; every VIGIE_* setting in .env.example/compose.yaml exists in server/src;
every file path cited in the docs exists (or exists on the named other branch); every `--flag` cited
in the docs is defined in server/src or deploy/ or is on the explicit list of third-party flags.
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
}
# Generated locally by the quick start, never committed (deploy/.gitignore).
GENERATED = {"deploy/.env", "deploy/certs/server.crt"}
errors: list[str] = []


def err(msg: str) -> None:
    errors.append(msg)
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


def check_yaml() -> None:
    for name in ("compose.yaml",):
        try:
            doc = yaml.safe_load((ROOT / "deploy" / name).read_text())
        except yaml.YAMLError as exc:
            err(f"{name} does not parse: {exc}")
            return
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
    ingest_vols = " ".join(doc["services"]["ingest"]["volumes"])
    if "vigie_overrides" in ingest_vols:
        err("ingest mounts the overrides volume")
    for svc in ("api", "pipeline"):
        if "vigie_overrides" not in " ".join(doc["services"][svc]["volumes"]):
            err(f"{svc} does not mount the overrides volume")
    for svc in ("ingest", "api"):
        for port in doc["services"][svc]["ports"]:
            if not str(port).startswith("${VIGIE_LAN_ADDR:?"):
                err(f"{svc}: port {port} does not use the required LAN address variable")
    print("yaml: ok")


def check_compose_config() -> None:
    tool = shutil.which("podman-compose")
    if not tool:
        print("podman-compose not installed: skipped")
        return
    with tempfile.TemporaryDirectory() as tmp:
        envfile = Path(tmp) / "env"
        envfile.write_text((ROOT / "deploy" / ".env.example").read_text())
        base = [tool, "--env-file", str(envfile), "-f", str(ROOT / "deploy" / "compose.yaml")]
        ok = subprocess.run([*base, "config"], capture_output=True, text=True, check=False)
        if ok.returncode != 0:
            err(f"podman-compose config failed: {ok.stderr[-300:]}")
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


def check_env_names() -> None:
    src = set(re.findall(r"VIGIE_[A-Z0-9_]+", source_text("server/src")))
    deploy_only = {  # consumed by deploy/ scripts and compose, not by the Python services
        "VIGIE_LAN_ADDR", "VIGIE_INGEST_PORT", "VIGIE_API_PORT", "VIGIE_IMAGE_TAG",
        "VIGIE_PIPELINE_INTERVAL_S", "VIGIE_LINK_OVERRIDES", "VIGIE_OVERRIDES_TARGET",
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


def check_paths() -> None:
    pat = re.compile(r"`((?:deploy|server|docs|api|collector|tests|tools)/[A-Za-z0-9_./-]+)`")
    link = re.compile(r"\]\(([A-Za-z0-9_./-]+\.(?:md|yaml|json))\)")
    for doc in DOCS:
        text = doc.read_text()
        cited = set(pat.findall(text))
        for target in link.findall(text):
            resolved = (doc.parent / target).resolve()
            if not resolved.exists():
                err(f"{doc.name}: link target {target} does not exist")
        for path in sorted(cited):
            if "<" in path or path.endswith("-") or "*" in path:
                continue
            if not path_exists(path):
                err(f"{doc.name}: cited path {path} does not exist (here or on its branch)")
    print("paths: ok")


def check_flags() -> None:
    known = source_text("server/src", "deploy") + (ROOT / "deploy/compose.yaml").read_text()
    # Flags of the router-side helper, which lives on another branch: verify them there.
    helper = subprocess.run(
        ["git", "show", "feat/conntrack-helper:collector/conntrack-helper/src/cli.rs"],
        cwd=ROOT, check=False, capture_output=True, text=True,
    ).stdout
    known += helper
    for doc in DOCS:
        for flag in sorted(set(re.findall(r"(?<![\w-])(--[a-z][a-z0-9-]+)", doc.read_text()))):
            if flag in THIRD_PARTY_FLAGS:
                continue
            if flag not in known:
                err(f"{doc.name}: flag {flag} is not defined in server/src or deploy/")
    print("flags: ok")


def main() -> int:
    check_yaml()
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

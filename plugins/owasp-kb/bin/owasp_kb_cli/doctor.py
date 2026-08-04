"""Check the install chain end to end, and report rather than repair.

Every failure mode in docs/install.md's troubleshooting table is silent: the plugin
loads, the server reconnects, the tools are simply absent or answering from a copy
that is not the one on disk. Prose describing those symptoms is an instruction with
no enforcement mechanism, and this project has already established that such
instructions rot. These are the same rows, executable.

One limit is stated in the output rather than only here: nothing on the host can
see which hooks the harness actually registered, so the hooks check verifies the
files the manifest names and says that is what it did.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from owasp_kb_cli.state import state_dir

MCP_DEFAULT = re.compile(r"\$\{OWASP_KB_IMAGE:-([^}]+)\}")


@dataclass(frozen=True)
class Result:
    ok: bool
    detail: str
    remedy: str = ""
    notes: tuple[str, ...] = ()


def plugin_root() -> Path:
    """The installed plugin directory this CLI is running from.

    CLAUDE_PLUGIN_ROOT when the harness sets it, otherwise the parent of bin/. It
    is reported rather than assumed: "am I looking at the installed copy or the
    repository" is the question a stale install makes unanswerable, and every other
    check reads its inputs from here.
    """
    if root := os.environ.get("CLAUDE_PLUGIN_ROOT"):
        return Path(root)
    return Path(__file__).resolve().parent.parent.parent


def _run(*command: str) -> subprocess.CompletedProcess:
    return subprocess.run(command, capture_output=True, text=True, check=False)


def check_plugin_identity() -> Result:
    root = plugin_root()
    manifest = root / ".claude-plugin" / "plugin.json"
    if not manifest.is_file():
        return Result(
            False,
            f"no plugin manifest at {manifest}",
            remedy="run this from an installed plugin, or set CLAUDE_PLUGIN_ROOT",
        )
    declared = json.loads(manifest.read_text()).get("version")
    if declared:
        return Result(
            False,
            f"running from {root}; the manifest declares version {declared}",
            remedy=(
                "drop the version field -- with it set, pushing commits does "
                "nothing for installed copies because the cache key never changes"
            ),
        )
    return Result(True, f"running from {root}; version resolves from the commit")


def pinned_image() -> str:
    """The image the plugin would run, honouring an OWASP_KB_IMAGE override."""
    if override := os.environ.get("OWASP_KB_IMAGE"):
        return override
    config = plugin_root() / ".mcp.json"
    match = MCP_DEFAULT.search(config.read_text())
    if not match:
        raise ValueError(f"no ${{OWASP_KB_IMAGE:-...}} default in {config}")
    return match.group(1)


def check_image_pinned() -> Result:
    image = pinned_image()
    if "@sha256:" not in image:
        return Result(
            False,
            f"the configured image is not digest-pinned: {image}",
            remedy=(
                "a tag is shadowed by any local image of that name; pin a digest "
                "from a published release"
            ),
        )
    return Result(True, f"pinned to {image}")


def check_image_present() -> Result:
    image = pinned_image()
    if _run("docker", "image", "inspect", image).returncode == 0:
        return Result(True, "the pinned image is present locally")

    probe = _run("docker", "manifest", "inspect", image)
    stderr = probe.stderr.lower()
    if probe.returncode != 0 and ("unauthorized" in stderr or "denied" in stderr):
        return Result(
            False,
            "the registry refused the pinned image",
            remedy="docker login ghcr.io   (a GitHub PAT with the read:packages scope)",
        )
    if probe.returncode != 0:
        return Result(
            False,
            f"the pinned image could not be reached: {probe.stderr.strip()[:200]}",
            remedy="check network access to ghcr.io",
        )
    return Result(
        False,
        "the pinned image is reachable but not present locally",
        remedy=f"owasp-kb doctor --pull   (or docker pull {image})",
        notes=(
            "otherwise the next session start pulls it, roughly 700 MB for the "
            "full variant, with no indication of why it is hanging",
        ),
    )


def check_server_answers() -> Result:
    image = pinned_image()
    if _run("docker", "image", "inspect", image).returncode != 0:
        return Result(
            False,
            "skipped: the image is not present, so the server was not started",
            remedy="owasp-kb doctor --pull",
        )
    requests = (
        '{"jsonrpc":"2.0","id":1,"method":"initialize","params":'
        '{"protocolVersion":"2025-06-18","capabilities":{},'
        '"clientInfo":{"name":"doctor","version":"0"}}}\n'
        '{"jsonrpc":"2.0","method":"notifications/initialized"}\n'
        '{"jsonrpc":"2.0","id":2,"method":"tools/call",'
        '"params":{"name":"kb_info","arguments":{}}}\n'
    )
    try:
        proc = subprocess.run(
            ["docker", "run", "-i", "--rm", "--network", "none", image],
            input=requests,
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return Result(
            False,
            "the server did not answer within 180s",
            remedy=f"docker run -i --rm --network none {image}",
        )
    # kb_info's response only. The whole exchange carries every tool description,
    # so searching all of it reports a mode that came from a description rather
    # than from the index -- the failure scripts/docker_smoke.sh documents.
    answer = next((line for line in proc.stdout.splitlines() if '"id":2' in line), "")
    if "server_version" not in answer:
        return Result(
            False,
            "the server did not answer kb_info",
            remedy=f"docker run -i --rm --network none {image}",
        )
    mode = "hybrid" if "hybrid" in answer else "lexical"
    return Result(True, f"the server answers; retrieval mode {mode}")


def check_hooks() -> Result:
    root = plugin_root()
    manifest = root / ".claude-plugin" / "plugin.json"
    limit = (
        "nothing on the host can see which hooks the harness registered, so this "
        "checks the files the manifest names"
    )
    if not manifest.is_file():
        return Result(False, f"no manifest at {manifest}. {limit}", remedy="reinstall the plugin")
    declared: list[str] = []
    for entries in json.loads(manifest.read_text()).get("hooks", {}).values():
        for entry in entries:
            for hook in entry.get("hooks", []):
                found = re.search(r"hooks/(\w+\.py)", hook.get("command", ""))
                if found:
                    declared.append(found.group(1))
    missing = [name for name in declared if not (root / "hooks" / name).is_file()]
    if missing:
        return Result(
            False,
            f"hook files the manifest names are absent: {missing}. {limit}",
            remedy="reinstall the plugin",
        )
    return Result(True, f"{len(declared)} hook files present. {limit}")


def check_state_dir() -> Result:
    directory = state_dir()
    if not directory.exists():
        return Result(
            True,
            f"{directory} does not exist yet; the server wrapper creates it on first run",
        )
    if directory.stat().st_uid == 0 and os.geteuid() != 0:
        return Result(
            False,
            f"{directory} is owned by root, so an assessment cannot write findings to it",
            remedy=f"sudo chown -R $(id -u):$(id -g) {directory}",
        )
    if not os.access(directory, os.W_OK):
        return Result(
            False,
            f"{directory} is not writable by this user",
            remedy=f"sudo chown -R $(id -u):$(id -g) {directory}",
        )
    return Result(True, f"{directory} is writable")


def check_docker() -> Result:
    if not shutil.which("docker"):
        return Result(False, "docker is not on PATH", remedy="install Docker")
    probe = _run("docker", "info")
    if probe.returncode != 0:
        detail = probe.stderr.strip().splitlines()[-1] if probe.stderr.strip() else "unknown error"
        return Result(
            False,
            f"the docker daemon is unreachable: {detail}",
            remedy="start the daemon, or add yourself to the docker group and log out and in",
        )
    return Result(True, "docker is usable")


def check_ssh_prerequisites() -> Result:
    """The marketplace is cloned over SSH, and Claude Code suppresses the
    interactive prompts for both the host fingerprint and the key passphrase. A
    missing known_hosts entry or an unloaded key therefore surfaces as an
    unexplained clone failure rather than as a question.
    """
    host = "github.com"
    if _run("ssh-keygen", "-F", host).returncode != 0:
        return Result(
            False,
            f"{host} is not in known_hosts, and the fingerprint prompt is suppressed",
            remedy=f"ssh-keyscan {host} >> ~/.ssh/known_hosts",
        )
    if _run("ssh-add", "-l").returncode != 0:
        return Result(
            False,
            "no keys loaded in ssh-agent, and the passphrase prompt is suppressed",
            remedy="ssh-add ~/.ssh/id_ed25519",
        )
    return Result(True, f"{host} is known and ssh-agent holds a key")


def check_marketplace_failure_mode() -> Result:
    if os.environ.get("CLAUDE_CODE_PLUGIN_KEEP_MARKETPLACE_ON_FAILURE") == "1":
        return Result(True, "a failed marketplace pull keeps the existing clone")
    return Result(
        True,
        "CLAUDE_CODE_PLUGIN_KEEP_MARKETPLACE_ON_FAILURE is unset",
        notes=(
            "without it a failed background pull deletes and re-clones the "
            "marketplace, so on a private repository behind a slow link each "
            "session repeats a 120-second timeout",
        ),
    )


CHECKS: list[tuple[str, Callable[[], Result]]] = [
    ("docker", check_docker),
    ("plugin", check_plugin_identity),
    ("pin", check_image_pinned),
    ("image", check_image_present),
    ("server", check_server_answers),
    ("hooks", check_hooks),
    ("state", check_state_dir),
    ("ssh", check_ssh_prerequisites),
    ("marketplace", check_marketplace_failure_mode),
]


def run(checks: list[tuple[str, Callable[[], Result]]] | None = None) -> int:
    """Every check, in order. Returns 1 if any failed."""
    failures = 0
    for name, check in CHECKS if checks is None else checks:
        try:
            result = check()
        except Exception as error:  # noqa: BLE001
            # doctor runs on a machine that is by definition misconfigured. A check
            # that raises must not take the remaining ones with it, or the first
            # problem hides every other one.
            result = Result(
                False,
                f"the check itself failed: {type(error).__name__}: {error}",
                remedy="report this; doctor should degrade rather than raise",
            )
        print(f"  {'ok  ' if result.ok else 'FAIL'} {name}: {result.detail}")
        for note in result.notes:
            print(f"       note: {note}")
        if not result.ok:
            failures += 1
            if result.remedy:
                print(f"       fix:  {result.remedy}")
    print(f"\n{'PASS' if not failures else f'{failures} check(s) failed'}")
    return 1 if failures else 0


def pull() -> int:
    image = pinned_image()
    print(f"pulling {image}")
    return subprocess.run(["docker", "pull", image], check=False).returncode

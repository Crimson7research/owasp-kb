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

    CLAUDE_PLUGIN_ROOT when the harness sets it, otherwise the parent of
    scripts/. It is reported rather than assumed: "am I looking at the installed
    copy or the repository" is the question a stale install makes unanswerable,
    and every other check reads its inputs from here.
    """
    if root := os.environ.get("CLAUDE_PLUGIN_ROOT"):
        return Path(root)
    return Path(__file__).resolve().parent.parent.parent


def invocation() -> str:
    """How a human runs this CLI, as a command that actually works.

    Derived from __file__ rather than written out: these tools are off PATH
    (ADR 0018), so a remedy naming a bare `owasp-kb` is a command-not-found at
    the exact moment someone is already stuck. The entry point sits one level up
    from this package.
    """
    return f"python3 {Path(__file__).resolve().parent.parent / 'owasp-kb'}"


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
        remedy=f"{invocation()} doctor --pull   (or docker pull {image})",
        notes=(
            "otherwise the next session start pulls it, roughly 700 MB for the "
            "full variant, with no indication of why it is hanging",
        ),
    )


# Tolerant of the escaping: kb_info's answer arrives as a JSON-RPC line whose result
# holds the tool's own JSON as text, so the quotes are backslashed. The rest of this
# check reads that line by substring for the same reason -- see the comment in
# check_server_answers about why the whole exchange is not searched.
REPORTED_VERSION = re.compile(r'server_version\\?"?\s*:\s*\\?"?(\d+\.\d+\.\d+)')


def recorded_version(record_text: str) -> str | None:
    """The version pinned-packs.json names, or None when there is nothing to compare.

    Three shapes collapse to None, and all three must stay silent: no record on disk
    (the caller passes an empty string), a record that cannot be parsed, and a record
    written before this field existed. A plugin copy without the field is not evidence
    of drift, so it must not make a correctly installed plugin fail its own doctor.
    """
    try:
        return json.loads(record_text).get("server_version") or None
    except json.JSONDecodeError:
        return None


def reported_version(answer: str) -> str | None:
    """The version kb_info's answer carries, or None if it names none."""
    found = REPORTED_VERSION.search(answer)
    return found.group(1) if found else None


def version_mismatch(answer: str, record_text: str) -> tuple[str, str] | None:
    """`(reported, expected)` when a server started from the image this copy pins
    reports a different version than this copy's own record names, or None.

    Both sides come from one plugin copy, so this is not a check on the server some
    session is talking to. What it catches is the record disagreeing with the image it
    names -- the release ordering having regressed so the digest was built before the
    version was written, or an OWASP_KB_IMAGE tag override that has moved.

    None when either side is silent, and that is deliberate in both directions: an
    absent record must not fail the check, and a server that did not answer kb_info is
    already reported by the caller -- turning it into a second failure about versions
    would send a reader after the wrong thing. `version_detail` distinguishes those
    silences from an agreement, because "None" alone cannot be printed as a match.
    """
    expected = recorded_version(record_text)
    reported = reported_version(answer)
    if not expected or not reported:
        return None
    return None if reported == expected else (reported, expected)


def version_detail(mode: str, answer: str, record_text: str) -> str:
    """check_server_answers' success detail, saying which comparison actually happened.

    Split out and pure because the string is the whole point of the check and the check
    around it needs docker to reach. This previously read "version matches" whenever
    `version_mismatch` returned None, which includes both silences: on a plugin copy
    predating the record it claimed a match having compared nothing.
    """
    expected = recorded_version(record_text)
    reported = reported_version(answer)
    if expected and reported:
        return f"the server answers; retrieval mode {mode}, version {expected} matches the record"
    if not expected:
        return f"the server answers; retrieval mode {mode}; the record names no version to compare"
    return f"the server answers; retrieval mode {mode}; the server named no version to compare"


def check_server_answers() -> Result:
    image = pinned_image()
    if _run("docker", "image", "inspect", image).returncode != 0:
        return Result(
            False,
            "skipped: the image is not present, so the server was not started",
            remedy=f"{invocation()} doctor --pull",
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
    # A record that exists but cannot be read is not evidence of drift. run()'s blanket
    # handler would otherwise turn a permissions problem into a failed server check,
    # which points a reader at the wrong thing.
    record = plugin_root() / "pinned-packs.json"
    try:
        recorded = record.read_text()
    except OSError:
        recorded = ""
    drift = version_mismatch(answer, recorded)
    if drift:
        reported, expected = drift
        # A digest is content-addressed: it cannot report two versions, and pulling it
        # again is inert, so `docker pull` is only a remedy when the image is a tag.
        remedy = (
            "the record and the image it names were built from different releases; "
            "check scripts/pin_image.py wrote both, and that release.yml still writes "
            "the version before it builds (ADR 0016)"
            if "@sha256:" in image
            else f"docker pull {image}   (then restart the session)"
        )
        return Result(
            False,
            f"the server reports version {reported}; the shipped record names {expected}",
            remedy=remedy,
            notes=(
                "both sides come from this plugin copy, so this does not say whether a "
                "session is talking to this image; it says the record disagrees with "
                "the image it names -- the release ordering having regressed, or a "
                "stale OWASP_KB_IMAGE tag override",
            ),
        )
    return Result(True, version_detail(mode, answer, recorded))


def check_hooks() -> Result:
    root = plugin_root()
    manifest = root / "hooks" / "hooks.json"
    limit = (
        "nothing on the host can see which hooks the harness registered, so this "
        "checks the files hooks/hooks.json names"
    )
    if not manifest.is_file():
        return Result(False, f"no hooks file at {manifest}. {limit}", remedy="reinstall the plugin")
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
            f"hook files hooks/hooks.json names are absent: {missing}. {limit}",
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
    """The marketplace is cloned over SSH, and Claude Code suppresses the interactive
    prompts for both the host fingerprint and the key passphrase, so a missing
    known_hosts entry or an unusable key surfaces as an unexplained clone failure
    rather than as a question.

    This asks whether SSH *authenticates*, rather than whether a particular
    precondition for it holds. It previously asserted `ssh-add -l` succeeds and
    reported a failure on a machine whose marketplace clone had just worked: a
    passphraseless key at a default path authenticates with no agent running at all.
    An empty agent is a cause to look at once authentication has already failed, not
    a requirement in itself.

    github.com exits 1 on a successful `-T`, so the exit code cannot be the signal
    and the greeting is matched instead. BatchMode keeps it from blocking on a
    prompt, and nothing here writes to known_hosts -- an unknown host is something
    to report, not to silently accept on the user's behalf.
    """
    host = "github.com"
    probe = _run("ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-T", f"git@{host}")
    output = f"{probe.stdout}{probe.stderr}"
    if "successfully authenticated" in output.lower():
        return Result(True, f"SSH to {host} authenticates")

    if _run("ssh-keygen", "-F", host).returncode != 0:
        return Result(
            False,
            f"{host} is not in known_hosts, and the fingerprint prompt is suppressed",
            remedy=f"ssh-keyscan {host} >> ~/.ssh/known_hosts",
        )
    if _run("ssh-add", "-l").returncode != 0:
        return Result(
            False,
            f"SSH to {host} did not authenticate, and no keys are loaded in ssh-agent",
            remedy="ssh-add ~/.ssh/id_ed25519",
        )
    return Result(
        False,
        f"SSH to {host} did not authenticate: {output.strip().splitlines()[-1][:160]}"
        if output.strip()
        else f"SSH to {host} did not authenticate",
        remedy=f"ssh -T git@{host} to see why; check the key is registered with GitHub",
    )


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

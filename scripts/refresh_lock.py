"""Bump sources.lock.yml to the newest upstream release and commit SHA.

Prints a human-readable summary of what changed. Does not commit or push; that
is the workflow's job, so the diff stays reviewable.
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.request
from pathlib import Path

LOCK = Path("sources.lock.yml")
API = "https://api.github.com/"


def _gh_json(path: str):
    """Query the public GitHub API.

    Unauthenticated is fine at 60 requests/hour for a weekly cron; a token is
    used when present purely to raise that limit.
    """
    request = urllib.request.Request(API + path, headers={"Accept": "application/vnd.github+json"})
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def latest_asvs_release() -> tuple[str, str]:
    """Newest non-bleeding-edge ASVS release tag and its version number."""
    for release in _gh_json("repos/OWASP/ASVS/releases"):
        tag = release["tag_name"]
        match = re.fullmatch(r"v(\d+\.\d+\.\d+)_release", tag)
        if match:
            return tag, match.group(1)
    raise RuntimeError("no versioned ASVS release found; only the bleeding-edge tag exists")


def latest_cheatsheets_commit() -> tuple[str, str]:
    """Newest cheat sheet commit SHA and its date as YYYYMMDD."""
    commit = _gh_json("repos/OWASP/CheatSheetSeries/commits/master")
    return commit["sha"], commit["commit"]["author"]["date"][:10].replace("-", "")


def main() -> int:
    text = LOCK.read_text(encoding="utf-8")
    original = text
    changes: list[str] = []

    release, version = latest_asvs_release()
    sha, date = latest_cheatsheets_commit()

    current_release = re.search(r"release: (\S+)", text)
    if current_release and current_release.group(1) != release:
        changes.append(f"ASVS release {current_release.group(1)} -> {release}")
        text = re.sub(r"release: \S+", f"release: {release}", text, count=1)
        text = re.sub(r"version: [\d.]+\n", f"version: {version}\n", text, count=1)
        # The asset filename embeds the version; bumping one without the other
        # would silently keep fetching the previous release's file.
        text = re.sub(
            r"OWASP_Application_Security_Verification_Standard_[\d.]+_en\.flat\.json",
            f"OWASP_Application_Security_Verification_Standard_{version}_en.flat.json",
            text,
        )

    current_sha = re.search(r"commit: ([0-9a-f]{40})", text)
    if current_sha and current_sha.group(1) != sha:
        changes.append(f"cheat sheets {current_sha.group(1)[:8]} -> {sha[:8]} ({date})")
        text = re.sub(r"commit: [0-9a-f]{40}", f"commit: {sha}", text, count=1)
        text = re.sub(r'version: "\d{8}"', f'version: "{date}"', text, count=1)

    if text == original:
        print("NO_CHANGES")
        return 0

    LOCK.write_text(text, encoding="utf-8")
    print("CHANGES")
    for change in changes:
        print(f"- {change}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

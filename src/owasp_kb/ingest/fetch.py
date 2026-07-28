"""Download pinned upstream sources into a local data directory."""

from __future__ import annotations

import subprocess
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

from owasp_kb.ingest.lock import Lock, LockedPack

RELEASE_ASSET_URL = "https://github.com/{repo}/releases/download/{tag}/{asset}"
RAW_FILE_URL = "https://raw.githubusercontent.com/{repo}/{ref}/{path}"
TIMEOUT_SECONDS = 60


def _run(cmd: list[str], cwd: Path | None = None) -> None:
    subprocess.run(cmd, cwd=cwd, check=True)


def _download(url: str, target: Path) -> None:
    """Fetch a public URL to disk, failing loudly with the URL on error."""
    try:
        with urllib.request.urlopen(url, timeout=TIMEOUT_SECONDS) as response:
            target.write_bytes(response.read())
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"HTTP {exc.code} fetching {url}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"could not fetch {url}: {exc.reason}") from exc


def fetch_release_pack(pack: LockedPack, dest: Path) -> Path:
    """Download release assets plus extra repo paths for a release-pinned pack.

    Asset names must be exact: a glob cannot be resolved over plain HTTPS.
    """
    out = dest / pack.name
    out.mkdir(parents=True, exist_ok=True)

    for asset in pack.assets:
        if "*" in asset or "?" in asset:
            raise ValueError(
                f"asset {asset!r} contains a glob; name release assets exactly in "
                "sources.lock.yml so they can be fetched over plain HTTPS"
            )
        _download(
            RELEASE_ASSET_URL.format(repo=pack.repo, tag=pack.release, asset=asset),
            out / asset,
        )

    for rel in pack.extra_paths:
        _download(
            RAW_FILE_URL.format(repo=pack.repo, ref=pack.release, path=rel),
            out / Path(rel).name,
        )
    return out


def fetch_commit_pack(pack: LockedPack, dest: Path) -> Path:
    """Clone a commit-pinned pack at its exact SHA."""
    out = dest / pack.name
    if not (out / ".git").exists():
        out.mkdir(parents=True, exist_ok=True)
        _run(["git", "init", "-q", str(out)])
        _run(["git", "remote", "add", "origin", f"https://github.com/{pack.repo}.git"], cwd=out)
    _run(["git", "fetch", "-q", "--depth", "1", "origin", pack.commit], cwd=out)
    _run(["git", "checkout", "-q", pack.commit], cwd=out)
    return out


def fetch_url_pack(pack: LockedPack, dest: Path) -> Path:
    """Download and unpack a pinned archive from a direct URL.

    Used by packs that are not on GitHub. The archive is expected to hold a
    single file; zipfile is stdlib, and `unzip` is not present in the
    devcontainer.
    """
    if not pack.url:
        raise ValueError(f"pack {pack.name!r} has no url to fetch")
    out = dest / pack.name
    out.mkdir(parents=True, exist_ok=True)
    archive = out / Path(pack.url).name
    _download(pack.url, archive)
    with zipfile.ZipFile(archive) as zf:
        names = zf.namelist()
        if len(names) != 1:
            raise ValueError(f"expected one file in {archive.name}, found {len(names)}: {names}")
        zf.extractall(out)
    return out


def fetch_all(lock: Lock, dest: Path) -> dict[str, Path]:
    """Fetch every pack. Returns pack name to local directory."""
    dest.mkdir(parents=True, exist_ok=True)
    paths = {}
    for name, pack in lock.packs.items():
        if pack.url:
            paths[name] = fetch_url_pack(pack, dest)
        elif pack.release:
            paths[name] = fetch_release_pack(pack, dest)
        elif pack.commit:
            paths[name] = fetch_commit_pack(pack, dest)
        else:
            raise ValueError(f"pack {name!r} pins neither a release nor a commit")
    return paths

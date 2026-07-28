"""Parse sources.lock.yml — the single source of truth for what content ships."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

import yaml


@dataclass(frozen=True)
class LockedPack:
    name: str
    type: str
    version: str
    license: str
    repo: str | None = None
    url: str | None = None
    release: str | None = None
    commit: str | None = None
    assets: list[str] = field(default_factory=list)
    extra_paths: list[str] = field(default_factory=list)
    paths: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Lock:
    packs: dict[str, LockedPack]


def load_lock(path: str | Path) -> Lock:
    text = Path(path).read_text(encoding="utf-8")
    raw = yaml.safe_load(text)
    packs = {}
    for name, cfg in raw["packs"].items():
        if cfg.get("release") == "latest":
            raise ValueError(
                f"pack {name!r} pins release 'latest', which is the ASVS bleeding-edge tag; "
                "pin an explicit release so citations stay reproducible"
            )
        # Match the path, not the whole URL and not just the filename. A
        # "/latest/" directory moves as upstream republishes into it, so a
        # pinned-looking filename underneath it is still not pinned; a host
        # like latest-cdn.example.com has no bearing on reproducibility and
        # should not be rejected.
        if "latest" in urlsplit(str(cfg.get("url", ""))).path:
            raise ValueError(
                f"pack {name!r} pins a url containing 'latest', which moves as "
                "upstream publishes; pin an explicit release or version so "
                "citations stay reproducible"
            )
        repo = cfg.get("repo")
        url = cfg.get("url")
        if repo is None and url is None:
            raise ValueError(f"pack {name!r} declares neither 'repo' nor 'url'; it needs one")
        if repo is not None and url is not None:
            raise ValueError(
                f"pack {name!r} declares both 'repo' and 'url'; it is ambiguous which "
                "one fetch should use, so pick one"
            )
        packs[name] = LockedPack(
            name=name,
            type=cfg["type"],
            repo=repo,
            url=url,
            version=str(cfg["version"]),
            license=cfg["license"],
            release=cfg.get("release"),
            commit=cfg.get("commit"),
            assets=cfg.get("assets", []),
            extra_paths=cfg.get("extra_paths", []),
            paths=cfg.get("paths", []),
        )
    return Lock(packs=packs)

"""Parse sources.lock.yml — the single source of truth for what content ships."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass(frozen=True)
class LockedPack:
    name: str
    type: str
    repo: str
    version: str
    license: str
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
        packs[name] = LockedPack(
            name=name,
            type=cfg["type"],
            repo=cfg["repo"],
            version=str(cfg["version"]),
            license=cfg["license"],
            release=cfg.get("release"),
            commit=cfg.get("commit"),
            assets=cfg.get("assets", []),
            extra_paths=cfg.get("extra_paths", []),
            paths=cfg.get("paths", []),
        )
    return Lock(packs=packs)

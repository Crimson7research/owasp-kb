"""Turn the Claude Code agent files into Codex custom agents, and install them.

Codex copies `agents/*.md` into its plugin cache and registers none of them: a
custom agent is a TOML file in `$CODEX_HOME/agents/`, and a plugin cannot declare
one yet. So a sync step writes them, generated from the Markdown rather than kept
as twins, which would drift (#96).

What does not translate, and what this does about it:

- `tools:` is an allowlist in Claude Code. Codex has none, so the role would
  inherit every tool. The allowlist is restated at the top of the instructions as
  a rule. That makes the separation instruction-only, which is a real loss.
- `model:` names Claude models. It is dropped, so the agent inherits the session's.
- `maxTurns:` has no Codex key and is dropped.
- The "Loading the knowledge base tools" section describes `ToolSearch`, which
  Codex has no use for. It is replaced by one sentence.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path

MANIFEST = ".owasp-kb-manifest.json"
MCP_PREFIX = "mcp__plugin_owasp-kb_owasp-kb__"
FRONTMATTER = re.compile(r"\A---\n(.*?)\n---\n(.*)\Z", re.DOTALL)
LOADING_SECTION = re.compile(r"(## Loading the knowledge base tools\n)(.*?)(?=\n## |\Z)", re.DOTALL)
CAPABILITIES = {
    "Read": "read files",
    "Grep": "search file contents",
    "Glob": "find files by name",
    "Bash": "run shell commands",
    "Task": "spawn the named custom agents",
}
NO_LOADING_STEP = (
    "The owasp-kb tools are MCP tools you can call directly by their plain names "
    "(for example `owasp_related`). There is no loading step."
)


def codex_home() -> Path:
    return Path(os.environ.get("CODEX_HOME") or Path.home() / ".codex")


def parse_agent(text: str) -> tuple[dict[str, str], str]:
    """Frontmatter keys and the body. The frontmatter is flat `key: value` lines."""
    match = FRONTMATTER.match(text)
    if not match:
        raise ValueError("agent file has no frontmatter")
    meta = {}
    for line in match.group(1).splitlines():
        key, _, value = line.partition(":")
        meta[key.strip()] = value.strip()
    return meta, match.group(2)


def allowed_capabilities(tools: str) -> list[str]:
    """What the Claude allowlist permitted, in plain words. ToolSearch only loaded
    other tools, so it grants nothing by itself."""
    names = [t.strip() for t in tools.split(",") if t.strip()]
    found = [CAPABILITIES[t] for t in names if t in CAPABILITIES]
    if any(t.startswith(MCP_PREFIX) for t in names):
        found.append("call the owasp-kb MCP tools")
    return found


def restate_allowlist(tools: str) -> str:
    allowed = allowed_capabilities(tools)
    if not allowed:
        return ""
    return (
        "Codex does not restrict this role's tools, so you must restrict yourself. "
        f"You may only: {', '.join(allowed)}. Use no other tool.\n\n"
    )


def rewrite_body(body: str) -> str:
    def replace(match: re.Match[str]) -> str:
        return f"{match.group(1)}\n{NO_LOADING_STEP}\n"

    return LOADING_SECTION.sub(replace, body).replace(MCP_PREFIX, "")


def toml_string(value: str) -> str:
    """A TOML basic string. JSON string escapes are a subset of TOML's."""
    return json.dumps(value, ensure_ascii=False)


def to_toml(text: str) -> tuple[str, str]:
    """(agent name, TOML text) for one Markdown agent file."""
    meta, body = parse_agent(text)
    instructions = restate_allowlist(meta.get("tools", "")) + rewrite_body(body).lstrip("\n")
    lines = [
        f"name = {toml_string(meta['name'])}",
        f"description = {toml_string(meta['description'])}",
        f"developer_instructions = {toml_string(instructions)}",
    ]
    return meta["name"], "\n".join(lines) + "\n"


def generate(agents_dir: Path) -> dict[str, str]:
    """File name to TOML text, for every agent file in `agents_dir`."""
    out = {}
    for path in sorted(agents_dir.glob("*.md")):
        name, text = to_toml(path.read_text())
        out[f"{name}.toml"] = text
    return out


def content_hash(files: dict[str, str]) -> str:
    digest = hashlib.sha256()
    for name in sorted(files):
        digest.update(name.encode() + b"\0" + files[name].encode() + b"\0")
    return digest.hexdigest()


def read_manifest(target: Path) -> dict:
    path = target / MANIFEST
    return json.loads(path.read_text()) if path.is_file() else {}


def sync(agents_dir: Path, home: Path, image: str) -> list[str]:
    """Write the generated agents into `home/agents`, prune what the manifest owns
    and the source no longer has, and return a line per action.

    A file that exists but is not in the manifest is a user's own agent. It is
    reported and left alone rather than overwritten.
    """
    files = generate(agents_dir)
    target = home / "agents"
    target.mkdir(parents=True, exist_ok=True)
    previous = set(read_manifest(target).get("files", []))
    actions, written = [], []
    for name, text in files.items():
        path = target / name
        if path.exists() and name not in previous:
            actions.append(f"skipped {name}: not written by owasp-kb, left alone")
            continue
        path.write_text(text)
        written.append(name)
        actions.append(f"wrote {name}")
    for name in sorted(previous - set(files)):
        (target / Path(name).name).unlink(missing_ok=True)
        actions.append(f"removed {name}: no longer shipped")
    manifest = {"files": written, "content_hash": content_hash(files), "image": image}
    (target / MANIFEST).write_text(json.dumps(manifest, indent=2) + "\n")
    return actions


def run_sync(pull: bool = False) -> int:
    """The `owasp-kb sync --host codex` command: print what changed, then what is left."""
    from owasp_kb_cli import doctor

    root = doctor.plugin_root()
    for action in sync(root / "agents", codex_home(), doctor.pinned_image()):
        print(f"  {action}")
    print(
        "\nCodex runs these only when nesting is allowed. The chapter orchestrator "
        "launches the finders, so set in config.toml:\n\n  [agents]\n  max_depth = 2\n"
    )
    print("Review the plugin hooks with /hooks if you have not since the last update.")
    return doctor.pull() if pull else 0

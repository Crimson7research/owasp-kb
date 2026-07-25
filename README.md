# owasp-kb

Authoritative OWASP security guidance — ASVS 5.0.0 and the Cheat Sheet Series —
served to AI coding agents as an MCP server, with citations, over stdio, offline.

This project is not affiliated with, endorsed by, or sponsored by the OWASP
Foundation. See [NOTICE](NOTICE).

## Why this exists

Ask an agent for secure-coding advice and it answers from training data: no
version number, no citation a reviewer can check, and often a release or two
behind whatever the client's compliance target actually requires. That advice
is frequently right and always unverifiable — there is no way to tell "this
matches ASVS 5.0.0 V6.2.1" from "this sounds plausible."

`owasp-kb` replaces that recall with retrieval. It ships the OWASP Application
Security Verification Standard and the OWASP Cheat Sheet Series, pinned to an
exact release and commit, chunked and cross-linked into a single SQLite index,
and exposes it over MCP so an agent calls a tool and gets back a citable
requirement id or cheat sheet anchor — not a paraphrase of what it remembers.

## Tools

Six tools cover search, navigation, checklist enumeration, and cross-references
between the two knowledge bases:

| Tool | Purpose |
|---|---|
| `kb_info` | Report which packs are loaded, their pinned versions, and the active retrieval mode (`lexical` or `hybrid`). Call first when unsure what content is available or when a citation needs an exact version string. |
| `owasp_search` | Hybrid (or lexical-only) search across ASVS requirements and Cheat Sheets for a natural-language security topic. Returns citable hits, never invented ones. |
| `owasp_outline` | Heading structure and section anchors for one document, so a large cheat sheet can be navigated instead of fetched whole. |
| `owasp_get` | Full text of a document, or one section by anchor. |
| `owasp_checklist` | Enumerate ASVS requirements filtered by chapter, section, id, or level — the tool for assessments and gap reports that need every applicable requirement, not the best-matching few. |
| `owasp_related` | Cross-reference a requirement, section, chapter, or cheat sheet doc_key across `guidance`, `cwe`, `supersedes`, and `nist` relationships. |

Full argument semantics, return shapes, error cases, and worked examples are in
[docs/tools.md](docs/tools.md).

## Skills and prompts

Four skills, installed with the plugin, trigger on the security topics an
agent is about to touch (authentication, sessions, injection, crypto, file
upload, and more — the full trigger list is in
[docs/discoverability.md](docs/discoverability.md)) and mandate a tool call
before any answer:

| Skill | Use when |
|---|---|
| `owasp-secure-coding` | Writing or reviewing code touching a security-relevant area |
| `owasp-asvs-verify` | Running a security assessment, pentest, or code audit against ASVS |
| `owasp-asvs-gap-report` | Producing a compliance report or gap analysis at a target ASVS level |
| `owasp-threat-model` | Reviewing an architecture or design before implementation |

Three MCP prompts ship with the server and surface as slash commands in
Claude Code:

| Prompt | Purpose |
|---|---|
| `asvs_chapter_review` | Walk one ASVS chapter as a verification pass |
| `cheatsheet` | Look up authoritative guidance on a topic and cite it |
| `asvs_gap_report` | Produce a complete gap report at a target level |

## Two variants

| Image | Retrieval | Size | Index |
|---|---|---|---|
| `owasp-kb:lite` | BM25 (lexical) | 246 MB | 4.8 MB |
| `owasp-kb:full` | Hybrid (BM25 + vector, RRF-fused) | 692 MB | 9.4 MB |

The embedder is the entire size difference (~446 MB). It also measurably
improves ranking: mean rank of the expected document across four paraphrased
queries goes from 3.0 (lexical) to 2.2 (hybrid) on the real corpus — see
[docs/architecture.md](docs/architecture.md) and ADR
`docs/decisions/0004-lite-and-full-variants.md` for the full measurement and
how the acceptance bar was corrected along the way.

## Install

The repository is currently **private**. The primary install path is a local
build (`make build`), not pulling from GHCR — the release workflow publishes
there, but you need access to this repo either way to build or pull.

```
git clone <this repo>
cd owasp-kb
make build        # builds both dist/owasp-kb-lite.sqlite and dist/owasp-kb-full.sqlite,
                   # then both owasp-kb:lite and owasp-kb:full images
```

**Claude Code**, from the cloned repo:

```
/plugin marketplace add /path/to/owasp-kb
/plugin install owasp-kb
```

**Any MCP-capable agent**, pointed at the built image directly:

```
claude mcp add owasp-kb -- docker run -i --rm --network none owasp-kb:full
```

(swap `owasp-kb:full` for `owasp-kb:lite` for the smaller, lexical-only image.)

**Codex or OpenCode**, via the install scripts — these copy the four skills
into place and print the exact MCP config snippet for that agent:

```
./install/codex.sh
./install/opencode.sh
```

Full commands for every path, plus a troubleshooting table, are in
[docs/install.md](docs/install.md).

## Runs offline

Every server invocation above passes `--network none`. That is not a default
worth reconsidering — the index is baked into the image at build time, so the
server needs no network access to answer anything, and none is granted. On a
client security engagement this matters directly: the tool never has an
egress path for the codebase being reviewed, works inside networks that are
deliberately locked down, and needs no allowlisting exception to pass a
client's own security review before it can be used on their systems.

## Reproducible citations

Standard `:lite` and `:full` tags move as sources are refreshed. Every release
also gets an immutable tag encoding the exact pinned content, for example
`owasp-kb:full-asvs5.0.0-cs20260724` — ASVS release `5.0.0`, Cheat Sheet Series
pinned at the commit dated `2026-07-24`. A citation produced against that tag
(`ASVS 5.0.0 V6.2.1`) resolves to the same requirement text for as long as the
image exists, independent of whatever `:full` points to later.

## Documentation

| File | Covers |
|---|---|
| [docs/architecture.md](docs/architecture.md) | Component diagram, the four units (`ingest/`, `core/`, `server/`, `plugin/`), schema, the `links` edge table, chunking rules |
| [docs/kb-packs.md](docs/kb-packs.md) | The pack contract, `checklist` vs `corpus`, and how to add a pack |
| [docs/tools.md](docs/tools.md) | Every tool's signature, arguments, return shape, errors, and a worked example |
| [docs/discoverability.md](docs/discoverability.md) | Why tool descriptions and skills are trigger-worded, and what was rejected |
| [docs/build.md](docs/build.md) | Lock file format, `make` targets, CI workflows, image tag scheme, mapping coverage |
| [docs/install.md](docs/install.md) | Every install path with exact commands, plus troubleshooting |
| [docs/licensing.md](docs/licensing.md) | The CC-BY-SA-4.0 / MIT split in full, and what a redistributor must do |

Design decisions — including the SQLite-over-Postgres call, the baked-index
trade-off, and why the project is Python — are recorded as ADRs in
`docs/decisions/`.

## Licensing

Code is MIT (see [LICENSE](LICENSE)). The ASVS and Cheat Sheet Series content,
and the SQLite index built from it, are CC-BY-SA-4.0 (see
[LICENSE-DATA](LICENSE-DATA)) — see [docs/licensing.md](docs/licensing.md) and
[NOTICE](NOTICE) for what that means for anyone redistributing this project or
its images.

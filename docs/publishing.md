# Publishing this repository

This project is developed against real targets. Assessment output names files, symbols and
defects belonging to whoever was assessed, and that material reaches more surfaces than it looks
like it does. This is the checklist for taking the repository public.

Run `scripts/preflight_publish.sh` for the mechanical part. The judgement parts are below it.

## The distinction that matters

**A history rewrite does not clean product.** Commit messages and the issue tracker are separate
problems with separate fixes. These surfaces survive any rewrite:

| Surface | Why it survives |
|---|---|
| `plugins/**` | ships in the plugin *and* is baked into the Docker image |
| `.claude/skills/**` | project skills, cloned with the repository |
| `src/**`, `docker/**`, `scripts/**` | the product |
| `README.md`, `docs/**` | published documentation |
| `dist/*.sqlite`, published images | built artefacts, carrying whatever went into them |

An example in an agent prompt is the easiest thing to get wrong, because it reads as
documentation while shipping as product. Four such examples in this repository once named a
private codebase's symbols; they illustrated their rules just as well once rewritten to describe
the *shape* instead of naming real code.

Plans and specs under `docs/superpowers/` are **gitignored** and never enter a tracked surface.
They are working artefacts of implementing one feature, abandoned once it lands, and they
accumulate assessment detail faster than anything else written here — so the cheapest control is
for them never to be committed at all.

**The issue tracker is the surface no script reaches.** `git grep` cannot see it and a rewrite
cannot touch it, yet it is where prose about a run naturally goes. Treat an issue body as a
published surface at the moment you write it. See the `anonymising-a-test-target` skill.

## Mechanical: the scrub

The pattern of identifiers to scrub is itself sensitive — a checklist that lists them leaks
them. So it lives outside version control:

```bash
cp .publish-scrub.example .publish-scrub   # gitignored
# add one identifier per line: repo names, symbol names, file paths, hostnames
scripts/preflight_publish.sh
```

The script greps every surviving surface and exits non-zero on a hit. It deliberately does **not**
check git history, and needs no exclusion for `docs/superpowers/` because that tree is gitignored.

Add identifiers as you assess new targets, not at publication time. The list is only as good as
the memory of whoever writes it, which is the weakness of this control and the reason the script
covers surfaces exhaustively rather than relying on recall of *where* something was written.

**Recall is not good enough to build the list, either.** Enumerate the targets from what is
written rather than from memory — a sweep over every revision found an entire second engagement
that recall had missed:

```bash
mapfile -t revs < <(git rev-list --all)
git grep -ahIoE '(the|a|an|second|first) [A-Za-z0-9_-]{2,20} (assessment|report|run|target)' \
  "${revs[@]}" -- | tr 'A-Z' 'a-z' | sort | uniq -c | sort -rn | head -30
```

Concrete descriptors stand out against the generic ones. Then **classify each match before
scrubbing it**: a blanket `/home/[a-z]+` pattern over this repository matches a devcontainer's
`ENV PATH=/home/dev/...`, an already-anonymous `/home/you` placeholder, and a `/home/solutions`
path inside an upstream CWE reference URL. Exactly one of the four was a leak. Over-scrubbing
corrupts fixtures and breaks builds, and it changed `plugins/` content here, which the digest
guard then correctly rejected.

## Judgement: what to keep

**The measurements are the valuable content, and they are safe.** Figures like *"0 of 72
unverified gaps carried a remediation citation"* or *"44% of cited CWE ids were not from the
knowledge base"* are aggregate and name nobody. They are also the strongest material in the
repository — they are why the design decisions are credible rather than asserted.

**Reasoning that referenced a target must be rewritten, not copied.** A finding that reads well
because it cites a real file path cannot be sanitised by find-and-replace; the surrounding
argument usually depends on the specifics. Rewrite it against a neutral example or drop it.

**The ADRs and `docs/stack.md` are already written for publication.** They quote measurements,
not targets. Reread them for tone rather than for leaks.

## Judgement: obligations

- **License texts ship in the image.** `LICENSE`, `NOTICE` and one license text per pack
  belong at `/opt/owasp-kb/licenses/`. An OCI `licenses` label is metadata, not the notice a
  redistributor is asked to carry forward.
- **Every pack's license is stated** in `docs/licensing.md`, with the trademark position for each
  upstream project.
- **Attribution names the upstreams** and links their repositories.
- **No OWASP endorsement is implied** — see the trademark note in `docs/licensing.md`.

## Judgement: coherence

- **The project name matches what it contains.** `owasp-kb` describes a server that once held two
  OWASP corpora. Non-OWASP packs make the name, `docs/stack.md`, `README.md` and ADR 0005
  progressively less accurate. Fix the descriptions or the name, but do not publish the
  contradiction.
- **The shipped image is pinned, and the pin is checked.** `src/owasp_kb/__init__.py` is the single
  version literal and `pyproject.toml` derives from it. The plugin manifests declare no version at
  all — Claude Code resolves it to the commit — so there is no version agreement left to assert.
  What is asserted instead is stronger: `plugins/owasp-kb/.mcp.json` must default to a
  digest-pinned GHCR reference (`test_the_default_image_is_pinned_by_digest`), and
  `scripts/verify_pin.sh` fails CI if that digest does not resolve or if the image it names does
  not carry the packs `sources.lock.yml` declares. Two images can report the same version and hold
  different indexes; only the digest tells them apart. See ADR 0014.
- **The test suite passes and the image smoke-tests clean** against `--network none`.

## Judgement: secrets

`grep` for tokens, keys and internal hostnames across everything, including
`.claude/settings.local.json` and any `.env`. CI runs the real ingest with no token by design, so
a credential appearing anywhere is an anomaly rather than a configuration.

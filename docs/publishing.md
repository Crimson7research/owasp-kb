# Publishing this repository

This project is developed against real targets. Assessment output names files, symbols and
defects belonging to whoever was assessed, and that material reaches more surfaces than it looks
like it does. This is the checklist for taking the repository public.

Run `scripts/preflight_publish.sh` for the mechanical part. The judgement parts are below it.

## The distinction that matters

**A history rewrite does not clean product.** Specs, plans, commit messages and the issue tracker
all disappear if you start a fresh repository. These do not:

| Surface | Why it survives |
|---|---|
| `plugins/**` | ships in the plugin *and* is baked into the Docker image |
| `.claude/skills/**` | project skills, cloned with the repository |
| `src/**`, `docker/**`, `scripts/**` | the product |
| `README.md`, `docs/**` outside `superpowers/` | published documentation |
| `dist/*.sqlite`, published images | built artefacts, carrying whatever went into them |

An example in an agent prompt is the easiest thing to get wrong, because it reads as
documentation while shipping as product. Four such examples in this repository once named a
private codebase's symbols; they illustrated their rules just as well once rewritten to describe
the *shape* instead of naming real code.

## Mechanical: the scrub

The pattern of identifiers to scrub is itself sensitive — a checklist that lists them leaks
them. So it lives outside version control:

```bash
cp .publish-scrub.example .publish-scrub   # gitignored
# add one identifier per line: repo names, symbol names, file paths, hostnames
scripts/preflight_publish.sh
```

The script greps every surviving surface and exits non-zero on a hit. It deliberately does **not**
check `docs/superpowers/` or git history — those are expected to contain assessment material and
are expected to be discarded.

Add identifiers as you assess new targets, not at publication time. The list is only as good as
the memory of whoever writes it, which is the weakness of this control and the reason the script
covers surfaces exhaustively rather than relying on recall of *where* something was written.

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

- **License texts ship in the image.** `LICENSE`, `LICENSE-DATA`, `NOTICE` and any per-pack terms
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
- **Versions agree.** `src/owasp_kb/__init__.py` is the single literal; `pyproject.toml` derives
  from it and `plugin.json` and `marketplace.json` are asserted equal. `scripts/docker_smoke.sh`
  fails the build if a shipped image reports a version its plugin does not.
- **The test suite passes and the image smoke-tests clean** against `--network none`.

## Judgement: secrets

`grep` for tokens, keys and internal hostnames across everything, including
`.claude/settings.local.json` and any `.env`. CI runs the real ingest with no token by design, so
a credential appearing anywhere is an anomaly rather than a configuration.

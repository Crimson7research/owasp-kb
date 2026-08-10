# 0014. Pin the plugin to an image digest, and let the commit be the plugin version

Date: 2026-08-04

## Status

Accepted. Refined by ADR 0015: `verify_pin.sh` holds the shipped digest to the packs
recorded for it at pin time, not to whatever `sources.lock.yml` declares on the
branch — the form below fails every content refresh, because the image for those
versions is not built until the release that follows the merge.

## Context

`plugins/owasp-kb/.mcp.json` defaulted to `owasp-kb:full`. An unqualified name
resolves to `docker.io/library/owasp-kb`, so docker checked the local store and
then failed against Docker Hub, where nothing exists. The plugin worked only for
someone who had run `make build` — which is why every documented install path
started with a local build even though `release.yml` publishes images.

Four references were available:

| Reference | Local image shadows remote? | Network per session start? |
|---|---|---|
| `owasp-kb:full` | always — the remote is unreachable | none |
| `ghcr.io/<owner>/owasp-kb:full` | yes — `--pull=missing` is docker's default and `docker tag` is unprivileged | first run only |
| the same, plus `--pull=always` | no | **every start** |
| `ghcr.io/<owner>/owasp-kb@sha256:…` | impossible — content-addressed | first run only |

Separately, the plugin cache is keyed on the resolved version, and that version was
a hand-maintained field in two manifests. Forgetting to bump it left the installed
copy unreachable rather than stale, with `/plugin`, `/mcp` and `/reload-plugins`
all reporting success about the wrong artefact. `scripts/plugin_digest.py` and
`content.sha256` existed to turn forgetting into a failing test.

## Decision

**Pin by digest.** `.mcp.json` defaults to
`ghcr.io/crimson7research/owasp-kb@sha256:…`. A digest cannot be shadowed: a local
cache hit on it *is* the published bytes, and it is pulled once rather than checked
every session.

`--pull=always` was rejected. It would put GHCR reachability and authentication on
the critical path of every server start, in a tool whose stated value is working
inside a network that is deliberately locked down. `--network none` is
container-side only, so pulling still works — it just has to happen once, not per
session.

The digest is only knowable after a push, so `release.yml` captures it and opens a
pull request. Merging that is the delivery step, because the marketplace is read
from the default branch.

**Let the commit be the plugin version.** Neither manifest declares `version`, so
Claude Code resolves it to the commit. Verified rather than assumed: a marker commit
moved an installed copy from cache key `37b3cef5e478` to `5fbc08c9a745` and
delivered the change.

**Delete the digest guard.** With the version keyed to the commit, a content change
shipped without a bump is not possible, so `scripts/plugin_digest.py` and
`content.sha256` are unnecessary rather than relocated. A five-line test asserting
the `version` field stays absent replaces sixty lines of tooling, and names what
would have to come back with the field.

**Delete the version-lockstep checks.** Three existed. `docker_smoke.sh` compared
the image's `server_version` to `plugin.json`'s version; `test_packaging.py`
asserted the package, plugin and marketplace versions equal; `test_tools.py`
compared `kb_info`'s `server_version` to the plugin's. All three were proxies for
"this image is the one published for this plugin", expressible only because a
moving tag could not state it. `scripts/verify_pin.sh` states it directly: the
shipped digest resolves, and the image it names carries the packs
`sources.lock.yml` declares.

Rewriting the third as equality with `owasp_kb.__version__` was tautological and
was caught being so — `kb_info` reads that attribute, so mutating the literal moved
both sides and the test stayed green. It asserts the field is present and
version-shaped instead, which is what a citation's provenance needs.

**Pin the base image too.** `python:3.13-slim` was a moving tag, so two builds of
identical source produced different images. `.github/dependabot.yml` bumps it and
the actions, since a digest pin stops security updates arriving on their own.

## Consequences

- A dev needs two grants: git access for the plugin and `docker login ghcr.io` for
  the image. SSH access to the repository does not authorise the registry, and
  neither implies the other.
- The first session after a pin changes pulls the image, roughly 700 MB for `full`.
  `owasp-kb doctor` reports this before it happens rather than leaving a session
  start to stall with no explanation.
- Master is the delivery surface, so a merge reaches devs on their next marketplace
  update. CI on `plugins/**` and PR review are the whole gate. This was chosen
  deliberately over a `stable` release branch.
- The package version and the plugin version now drift on purpose. An image is
  released when its content changes; the plugin ships on every commit.
- `bin/owasp-kb-report` became `bin/owasp-kb`, carrying `report merge`, `doctor`
  and `sessions`. ADR 0013 names the old script because that is what existed when
  it was written.
- Images are amd64 only. Every dev is on Linux amd64, so multi-arch is deferred
  until that stops being true.
- Automatic expiry of session state was considered and rejected for now: the
  material is engagement output and deleting it is a person's decision.
  `owasp-kb sessions` makes it visible and clearable instead.

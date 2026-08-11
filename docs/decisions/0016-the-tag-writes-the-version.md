# 0016. The tag writes the version, before anything is built

Date: 2026-08-11

## Status

Accepted. Refines ADR 0015.

## Context

`__version__` in `src/owasp_kb/__init__.py` is the single version literal in this
repository. It versions the Python package and the image built from it, `pyproject.toml`
derives from it, and `kb_info` reports it as `server_version`. Until now it was bumped by
hand, in a commit made before a `v*` tag was cut.

At `v0.17.1` the bump was skipped. That tag's `__init__.py` still declared `0.17.0`, so
the image published for it reports the *previous* release's number — and nothing failed.
No test compares a tag to the literal, and the only test that mentions `__version__` at
all asserts that `pyproject.toml` derives from it, which is true whatever the literal
says. A step that exists only in someone's memory of the release procedure is not part of
the release.

The cost was not the wrong number in a response. `kb_info`'s own description tells a
caller to compare `server_version` against the plugin version it expects, and it says so
precisely because a reconnect reports success whether or not the image behind it is
current. That comparison is the only staleness detector this project has, and a skipped
bump breaks it in the direction that matters: a stale server becomes indistinguishable
from a fresh one.

It cost exactly that, once. A session read `0.17.0` from a server while the plugin pinned
the `v0.17.2` image, and could not tell whether it was holding a stale local image or
looking at a release that had skipped its bump — two different problems with two different
fixes, and the number alone does not separate them. It was later confirmed to be a stale
image, by querying `kb_info` against the pinned digest directly, which returns `0.17.2`.

## Decision

**The tag writes the literal.** `release.yml` derives the version from `github.ref_name`
and runs `scripts/set_version.py --tag … --write` in the step immediately after
`setup-python`, before the `Install` step and therefore before any index, image or wheel
exists. The pin pull request then carries that same edit to the default branch alongside
the digest and the pack record.

The write happens twice in one run — into the build tree, and into the branch the pull
request opens — and that is not redundancy. **A bump carried only by the pull request
cannot work**, because the image is built and pushed before the pull request exists. An
edit landing only there fixes the repository and leaves the published artefact reporting
the previous release: the `v0.17.1` shape reached by a different route, one release later.
The ordering is the whole mechanism, so
`test_the_release_writes_the_version_before_it_builds_anything` compares the positions of
the named steps in the workflow rather than merely asserting the step exists — a
reordering that reintroduces the failure is invisible in a diff.

**Nothing checks monotonicity.** A tag that goes backwards, or repeats a version already
published, is accepted and written. What is refused is a string that is not a version at
all: `set_version.py` matches `vX.Y.Z` only, so a malformed tag cannot become a published
build's identity. Ordering tags is a human decision with no local evidence to check it
against; a malformed one is a typo the script can see.

Two alternatives were rejected:

- **Resolve the version from the tag with setuptools-scm**, removing the literal
  entirely. This is the stronger form of the same idea — nothing to write means nothing to
  forget. It does not fit here: `set_version.py` runs before the `Install` step, so there
  is no installed distribution to read metadata from at that point, and every untagged
  build (CI, local, an editable dev container) would report a derived dev version rather
  than the release it was cut from. The literal is also read as a module attribute
  specifically so an editable install cannot report a stale number.
- **A `make release` target** doing bump, commit and tag together. It upholds the
  invariant only when it is used, which is the property that already failed once. A
  workflow triggered by the tag cannot be bypassed by cutting the tag another way.

## Consequences

- The version reaches the default branch only when the pin pull request merges. Between
  publish and merge, master names the previous release while the registry holds the new
  one. That direction of drift is already tolerated for packs — `verify_pin.sh` reports
  it rather than failing, by ADR 0015 — and this is the same window.
- A release that publishes images and then fails to open the pin pull request leaves
  master behind the registry, and a Release drafted rather than published. That is why
  the Release is a draft: an incomplete release should read as incomplete.
- `plugins/owasp-kb/pinned-packs.json` gained a `server_version` field, so `doctor` can
  compare what the running server reports against what the plugin shipped and name both
  numbers. Naming both is what makes a stale image distinguishable from a skipped bump —
  the question the original session could not answer.
- A pre-release version is now unrepresentable. `vX.Y.Z` only, matching every release cut
  so far and the image tag scheme, which has never carried a pre-release form. Adding one
  means changing the pattern and whatever downstream consumes the tag, deliberately.

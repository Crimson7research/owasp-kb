# 0015. Record the packs a pinned image holds, rather than reading the lock

Date: 2026-08-10

## Status

Accepted. Refines ADR 0014.

## Context

`scripts/verify_pin.sh` checked the digest `plugins/owasp-kb/.mcp.json` ships against
the pack versions in the working tree's `sources.lock.yml`. That reads as the right
invariant — the shipped image holds the declared content — and it is wrong by one
step of the release order.

The lock is bumped by `refresh.yml`, which opens a pull request. The image holding
the new content does not exist until a `v*` tag runs `release.yml`, and the digest
naming it is not knowable until that push. So on every content refresh the check
asks the previous release's image to report versions that were pinned after it was
built.

The first refresh pull request ever opened, #50, failed on exactly this:

```
FAIL: pack cheatsheets should report 20260805 and does not
```

with a clean `test` job and content that `refresh.yml` had already fetched and built.
The failure was unfixable inside the pull request — no commit on that branch could
make a published image hold content published after it — and `sources.lock.yml` is
not in `ci.yml`'s `paths-ignore`, so merging would have turned master red until a
release was cut and its pin pull request merged.

The check was not wrong to exist. It replaced three version-lockstep proxies (ADR
0014) and it is the only thing standing between a citation and an image that does
not hold what it claims. What it lacked was a statement of *when* the image was
expected to be current.

## Decision

**Record the packs at pin time.** `scripts/pin_image.py` writes
`plugins/owasp-kb/pinned-packs.json` alongside the digest it writes into `.mcp.json`:

```json
{
  "image": "ghcr.io/crimson7research/owasp-kb@sha256:…",
  "packs": {"asvs": "5.0.0", "cheatsheets": "20260724", "cwe": "4.20"}
}
```

It runs inside `release.yml` at the commit being released, so the lock it reads is
the one the image was built from. Both files travel in the release pin pull request;
`add-paths` names both, because a pull request carrying one without the other ships a
claim about the wrong image.

**Verify against the record, not the lock.** `verify_pin.sh` now fails when the
recorded digest is not the one the plugin ships, or when the image does not report
the versions recorded for it. Those are the two ways a citation's provenance can be
false, and neither depends on where the lock has moved since.

**Report lock drift without failing.** Between a refresh landing and the release that
ships it, the lock is ahead of the image by design, so the run prints:

```
note: sources.lock.yml is ahead of the shipped image -- a release is pending
  cheatsheets: shipped 20260724, lock 20260805
```

Reported rather than silent: a release that never happened otherwise looks identical
to one that did, and the drift is the only visible trace of it.

**Assert the two files agree in the unit suite.** `test_the_pack_record_describes_the_image_the_plugin_ships`
fails when the record names some other digest — that check needs no registry and no
docker, and it catches the release that wrote one file and not the other. The
companion check on pack *names* is a subset, deliberately: requiring equality with
the lock would recreate this same deadlock the first time a fourth pack is added.

## Consequences

- A content refresh is mergeable on its own, and master stays green until the release
  that ships it. The release closes the drift the notice describes.
- The claim CI enforces is narrower and true: *this digest holds these packs*. That
  the shipped packs are the latest available is a separate question, and the drift
  notice — plus the refresh pull request itself — is where it is answered.
- One more file must reach master for a release to be complete. A pin pull request
  merged without the record leaves `verify_pin.sh` checking a new image against the
  previous release's versions, which is why the unit test above fails instead.
- Hand-editing a digest into `.mcp.json` now fails CI rather than passing. Use
  `scripts/pin_image.py --image <ref> --write`, which writes both files.

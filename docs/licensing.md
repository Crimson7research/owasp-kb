# Licensing

This is a practical reading for people deciding whether and how they can use,
modify, or redistribute this project — **not legal advice.** If a licensing
question actually matters to you (a commercial redistribution, a client
deliverable, a fork you plan to publish), read the full texts in
[LICENSE](../LICENSE) and the per-pack texts under [licenses/](../licenses/)
yourself, or ask a lawyer.

## Both upstream repos are CC-BY-SA-4.0

Two of the three projects this repository ingests content from:

- [OWASP/ASVS](https://github.com/OWASP/ASVS)
- [OWASP/CheatSheetSeries](https://github.com/OWASP/CheatSheetSeries)

both license their content **CC-BY-SA-4.0** ("Attribution-ShareAlike"),
verified directly via the GitHub licence API on each repository rather than
assumed from an OWASP-wide default. Neither project's content is MIT, Apache,
or public domain — anything derived from either carries the same license
forward, by the terms of ShareAlike, whether or not that derivation is
obvious.

## Why redistribution and adaptation both apply here

Two separate CC-BY-SA-4.0 obligations are in play, not one:

- **Baking the content into a distributable image is redistribution.** The
  `owasp-kb:lite` and `owasp-kb:full` images ship the actual ASVS and Cheat
  Sheet Series text, verbatim, inside the SQLite file each image bakes in at
  `/opt/owasp-kb/owasp-kb.sqlite`. Anyone who pulls or receives that image
  receives a copy of the licensed content, which is exactly what
  "redistribution" means under the license — the attribution requirement
  applies in full, regardless of the fact that it arrives inside a database
  file rather than as loose markdown. The same is true of the CWE catalogue's
  entry text, which the same file carries verbatim; its obligation comes from
  MITRE's terms rather than from CC-BY-SA-4.0, and it is the reason LICENSE-CWE
  travels with the image — see
  [below](#cwe-is-mitres-under-its-own-terms).

- **The built SQLite index is itself an adaptation, so ShareAlike applies to
  it independently.** The index is not the source content unmodified — it is
  chunked at heading boundaries, cross-linked against the other pack via the
  `links` edge table, re-keyed by requirement id and doc anchor, and (in the
  `full` variant) embedded into a vector representation. That is
  transformation, not mere repackaging, and CC-BY-SA-4.0's ShareAlike clause
  requires anything built *from* the licensed material to carry forward the
  same license — the derived index is CC-BY-SA-4.0 in its own right, not
  merely "contains CC-BY-SA-4.0 content." This is why each pack's license text
  is vendored under [licenses/](../licenses/) alongside [LICENSE](../LICENSE),
  rather than the project simply linking to the upstream repos and calling the
  licensing question closed.

## The code/data split

Four licenses cover four disjoint things in this repository, one per pack plus
the code, and none of them covers another:

- **[LICENSE](../LICENSE) (MIT)** covers this project's own source code only:
  the ingest pipeline (`ingest/`), the domain model and retrieval logic
  (`core/`), the MCP server (`server/`), and the Claude Code plugin and skills
  (`plugins/`). None of that code is derived from OWASP's content — it is
  original tooling written to serve that content.
- **[LICENSE-OWASP-ASVS](../licenses/LICENSE-OWASP-ASVS) (CC-BY-SA-4.0)**
  covers the ASVS content as fetched, and the portion of the SQLite index built
  from it, wherever either appears — inside `dist/*.sqlite`, inside the baked
  images, or in any redistribution of either.
- **[LICENSE-OWASP-CHEATSHEET](../licenses/LICENSE-OWASP-CHEATSHEET)
  (CC-BY-SA-4.0)** covers the Cheat Sheet Series and its portion of the index,
  on the same terms. It is a copy of the file above, because both projects
  chose the same license; they are pinned separately in `sources.lock.yml` and
  either could be relicensed without the other, which is why there are two
  files and not one.
- **[LICENSE-CWE](../licenses/LICENSE-CWE)** covers MITRE's CWE terms of use,
  under which the CWE pack's content is used — see
  [below](#cwe-is-mitres-under-its-own-terms).

Each Docker image's OCI labels state this split directly
(`org.opencontainers.image.licenses="MIT AND CC-BY-SA-4.0 AND
LicenseRef-CWE-TOU"`), so the split is visible from the image metadata alone,
without reading this document.

## What a redistributor must do

Anyone redistributing an `owasp-kb` image, or the index file it bakes in,
should at minimum:

1. **Preserve attribution** to both upstream projects — name them, link to
   their repositories, and state their license (CC-BY-SA-4.0) — this
   repository's [NOTICE](../licenses/NOTICE) file is one way to satisfy this and
   can be carried forward as-is.
2. **Carry the CC-BY-SA-4.0 license forward** for the content and the index
   specifically (not necessarily for any of your own original code built
   around it) — a straightforward reading is to keep the license text of every
   pack you redistribute alongside the artifact, which for a whole image means
   all of [licenses/](../licenses/). Carry [LICENSE-CWE](../licenses/LICENSE-CWE)
   forward too, for the same reason — CWE's terms of use require it.
3. **State what changed**, if anything, beyond what this project already
   states (chunking, cross-linking, embedding) — CC-BY-SA-4.0 asks that
   modifications be indicated.
4. **Not imply OWASP endorsement** — see the trademark note below,
   independent of the copyright license entirely.

## CWE is MITRE's, under its own terms

The CWE pack carries MITRE's Common Weakness Enumeration, pinned to a numbered
release. Its terms are permissive and explicit:

> CWE™ is free to use by any organization or individual for any research,
> development, and/or commercial purposes, per these CWE Terms of Use.

Two obligations follow. The terms must accompany redistribution, which is why
[LICENSE-CWE](../licenses/LICENSE-CWE) is vendored here rather than fetched at
build time — a legal notice should not change silently between builds, and an
image that runs with `--network none` cannot fetch one. And `CWE™` is a
MITRE trademark: naming the catalogue is attribution, not endorsement, and
MITRE disclaims warranty and liability for any use of it.

CWE is **not** an OWASP project. It sits in this server because ASVS maps to it,
not because it shares an upstream.

## Trademark disclaimer

OWASP® is a registered trademark of the OWASP Foundation. This project is
**not affiliated with, endorsed by, or sponsored by** the OWASP Foundation.
The project name leads with "owasp" only because that is what most of the content
is — the Application Security Verification Standard and the Cheat Sheet Series,
both OWASP Foundation projects — not because of any relationship with the
Foundation itself. Since the CWE pack, the name is also **incomplete** as a
description: one of the three packs is MITRE's, and the name says nothing about it.
`kb_info` reports every pack's `license` and `source_url` for that reason, so a
citation's upstream is always recoverable from the server rather than inferred from
the repository's name. This matters specifically because the naming choice could
otherwise read as an implied affiliation; the disclaimer exists precisely to
foreclose that reading, and is repeated in [NOTICE](../licenses/NOTICE).

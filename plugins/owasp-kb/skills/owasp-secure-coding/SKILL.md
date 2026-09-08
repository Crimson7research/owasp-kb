---
name: owasp-secure-coding
description: Use when writing, reviewing, refactoring, moving, renaming, extracting, triaging, diagnosing or planning any change to code touching authentication, passwords, MFA, sessions, cookies, tokens, JWT, OAuth, OIDC, authorization, access control, input validation, SQL injection, command injection, LDAP injection, SSRF, XSS, XXE, IDOR, path traversal, directory traversal, open redirect, server-side template injection, privilege escalation, output encoding, deserialization, file upload, file download, cryptography, TLS, key management, secrets, API keys, credentials, connection strings, base URLs, outbound requests, redirects, logging, error handling, CSRF, CORS, security headers, GraphQL, WebSocket, WebRTC, or API endpoints. Applies to refactors and mechanical-looking field moves, not only to new features. Absence of security framing in the request is not evidence of absence of security relevance. Applies while the approach is still being chosen, not only once code exists. Retrieves the applicable OWASP Cheat Sheet guidance and ASVS requirements, and checks whether the codebase already has the control, before the code is written.
---

# Secure coding with OWASP guidance

Announce first: **Using owasp-secure-coding to retrieve the applicable OWASP guidance before this change is written.**

Retrieve authoritative guidance before writing or approving security-relevant code.

## Why call the tools rather than answer from recall

You may already know the vulnerability class. That is not the question. The question
is whether you can enumerate every dimension a correct fix has to cover, and you
cannot check that from the inside.

A worked case. A triage session diagnosed an SSRF defect and proposed an allowlist
-- correct in shape, since ASVS V1.3.6 asks for exactly that. It covered domains,
paths and ports and never mentioned protocols, which is the first dimension the
requirement names. It also proposed resolve-then-connect validation, which the SSRF
cheat sheet documents as bypassable via DNS pinning. Neither gap was visible from
inside the reasoning that produced the plan, and the session's own explanation for
skipping this skill was that it would add "process overhead without new insight".

A second case. Another session reached the correct requirement and still nearly
shipped two defects, because the corpus cannot see the codebase. It was about to write
a fresh URL validator while a shared guard in the same repository already covered
schemes, hostnames and operator-configured network exceptions; and it was about to
"fix" redirect-following by disabling redirects, where that guard already re-validated
every hop — the disabling would have broken legitimate destinations while handling the
attack worse. A citation proves you read the requirement. It does not prove the control
is missing.

The corpus gives you two things recall cannot: a **citable id** a reviewer can
check, and an **enumeration** of what the fix must address. Call the tools before
choosing the approach, not to confirm one you have already chosen -- a search run to
validate a decision does not surface what that decision already excluded. What neither
gives you is whether this codebase already satisfies the requirement. That comes from
the codebase, and no citation stands in for it.

## Process

1. **Name the data flow. Do not judge relevance.** For each field, config key, route or
   parameter the change touches, write one sentence saying where the value comes from,
   where it is stored, and what it is used to do. This is a factual description of the
   code and needs no security vocabulary — which is the point, because deciding whether a
   change "is security work" is the judgement that fails. A field move is a change.

2. **Decide which checklist governs, before probing anything.** ASVS is written for web
   applications and their server endpoints. If the code under change runs *on the device* —
   Android or iOS native, React Native, Flutter, or any app-side module — the governing
   checklist is `pack="masvs"`, and ASVS covers only the server endpoint the app talks to,
   not the code in front of you.

   **Adapting an ASVS requirement to a device-side control by analogy is not permitted.**
   A session diagnosing a mobile finding noted in its own reasoning that the requirement was
   written for a web application, argued from that reasoning that it applied anyway, and
   cited it anyway. The citation then resolved to a web-scoped requirement — the one thing a
   citation is for, a reviewer checking it against the code, failed. Cite the MASVS control
   instead.

   MASVS controls are deliberately coarse — 8 groups, 24 controls, one sentence each plus a
   description. Where the corpus holds no implementation detail for the fix, **say that in the
   answer** rather than reaching for an ASVS requirement that reads close enough. MASVS has no
   levels: do not pass `level` with `pack="masvs"` — it raises `ValueError`.

3. **Probe the cheat sheets with those sentences.** Call `owasp_search` with
   `pack="cheatsheets"`, once per sentence. The rule is to phrase the probe as origin and
   use, not as a type. Cheat sheet titles and bodies are topic-shaped, so mundane wording
   reaches them — `api key supplied by an operator, stored in the database` returns
   `Symfony_Cheat_Sheet#sensitive-data` and `REST_Security_Cheat_Sheet#api-keys`, with no
   security vocabulary in the query at all. A noun plus its *type* reaches less: `base url
   for outbound http client` never reaches the SSRF sheet, at any depth the search returns,
   and reaches the unvalidated-redirect sheet only at rank 28 — past the default window
   entirely. `url supplied by an operator, used to make a request from the server` instead
   puts `Unvalidated_Redirects_and_Forwards_Cheat_Sheet#dangerous-forward-example` at the
   top, whose `#validating-urls` section cross-references the SSRF cheat sheet's
   URL-validation guidance. Follow those cross-references by calling `owasp_outline` on the
   referenced document rather than passing the inline anchor to `owasp_get`: a
   cross-referenced anchor is not necessarily an indexed one. That link points at
   `#application-layer`, an h5 the index does not carry, so `owasp_get` answers `unknown
   anchor` and lists the ones it has. **Do not answer from memory** — recalled security
   advice is often a version out of date and carries no citation a reviewer can check. An
   empty result is cheap and is itself an answer.

4. **Narrow before fetching.** Cheat sheets reach 37,000 characters. Call `owasp_outline`
   on the best-matching `doc_key`, pick the relevant anchor, then `owasp_get` that section
   only.

5. **Cross to ASVS with the vocabulary the sheet just supplied.** Cheat sheets describe
   implementation mistakes; ASVS states what is *required* at each level. The phrasing rule
   inverts between the packs, so do not reuse the data-flow sentence here. Mundane
   origin-and-use wording reaches the cheat sheets because their titles are topic-shaped;
   ASVS requirement text is normative security prose, and it is reached by the register the
   sheet you just read writes in — the name of the vulnerability class, the name of the
   control. Search `pack="asvs"` with those. Measured: `url supplied by an operator, used to
   make a request from the server` returns exactly two requirements against `pack="asvs"`, an
   OIDC issuer-metadata check and an L3 parser-consistency requirement, and never reaches
   `V1.3.6` at any depth the search returns. Words lifted from the sheet do: `SSRF allowlist
   input validation domain name IP address URL` returns `V1.3.6` and nothing else, and a
   paraphrase in the same register — `SSRF allowlist validate outbound request destination` —
   returns `V1.3.6` first and `V13.2.4` second. The class and control names reach the
   requirement about the code and stop near it, so where a configuration or deployment layer
   is in scope, widen with more of the sheet's own phrasing: `SSRF allowlist of identified
   and trusted applications the server may call, network layer firewall allowed routes` puts
   `V13.2.4` first and `V1.3.6` second, where the shorter query never returned `V13.2.4` at
   all. Then call `owasp_related(<req_id>, rel="guidance")` to confirm the sheet you read is
   the one mapped to that requirement. The reverse hop does not exist — passing a cheat sheet
   `doc_key` to `owasp_related` returns no edges — so do not read that emptiness as the
   corpus having no mapping.

6. **Establish precedence with the vocabulary the corpus just gave you.** Call `Grep` on
   the codebase for the control names the guidance named — allowlist, scheme, guard,
   connect, redirect, whatever it used — and not for names you thought of before reading.
   If the corpus returned nothing, grep for the control names you would have expected and
   say in your answer that those terms are yours, not the corpus's. Then either extend the
   control that already exists or state why it does not fit. Do not write a validator, guard
   or middleware of your own before this step has run.

7. **Cite everything.** Every security claim carries its citation inline — `ASVS 5.0.0
   V6.2.1` or `Authentication_Cheat_Sheet#password-storage`. Get the exact version from
   `kb_info`.

8. **Write the code**, then state which requirements it satisfies and which it does not.

## If the knowledge base is unreachable

Say so explicitly and make no citations. Do not fall back on recalled guidance while
appearing to have consulted the knowledge base — that is worse than no guidance, because the
citations are missing and nobody can tell the difference until it matters. One step survives
the outage: step 6 is a local `Grep`, and it is the step that prevented two defects. Still
check whether the codebase already has the control, searching for the control names you
would expect, and say in your answer that those terms are yours and not the corpus's.

## If the pack is not in this image

The plugin and the packs it queries ship separately: skills are versioned with this
repository, but a pack such as `masvs` only exists once a built server image includes it.
`kb_info` reports which packs the running server actually holds — the same call you use to
get the version string for a citation. If `masvs` is not among them, the image predates the
pack. That is a deployment state, not a reason to substitute.

Say so explicitly in the answer: name the control area that has no citable requirement in
this image, and state plainly that the mobile requirement set is not present. An honest gap
is a usable answer — a reviewer can act on it.

**Falling back to an adapted ASVS requirement is still not permitted, and this is the case
where the temptation is strongest.** You have just been told the mobile dimension matters,
and ASVS is the only thing that will answer. Reaching for it anyway reproduces the exact
failure step 2 exists to prevent — a web-scoped requirement cited for a device control, with
a reviewer unable to tell from the citation alone. Do not adapt one because the mobile pack
happens to be unavailable this session.

`Mobile_Application_Security_Cheat_Sheet` **is** in the corpus and is a legitimate citation
for implementation guidance here — probe it with `owasp_search`/`owasp_outline` against
`pack="cheatsheets"` as usual. It is not a requirement set and does not substitute for a
MASVS control id, but it is better than recall and better than a mis-scoped ASVS id.

For the human reading the answer: the remedy is an image built from a revision that ships
the pack. `kb_info`'s `server_version` together with the digest recorded in
`pinned-packs.json` is how you tell which one is running.

## Notes

- Prefer L1 and L2 requirements unless the user states a higher target level.
- When guidance and existing codebase patterns conflict, surface the conflict rather than
  silently following either.

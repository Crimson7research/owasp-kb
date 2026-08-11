---
name: owasp-secure-coding
description: Use when writing, reviewing, refactoring, moving, renaming, extracting, triaging, diagnosing or planning any change to code touching authentication, passwords, MFA, sessions, cookies, tokens, JWT, OAuth, OIDC, authorization, access control, input validation, SQL injection, command injection, LDAP injection, SSRF, XSS, XXE, IDOR, path traversal, directory traversal, open redirect, server-side template injection, privilege escalation, output encoding, deserialization, file upload, file download, cryptography, TLS, key management, secrets, API keys, credentials, connection strings, base URLs, outbound requests, redirects, logging, error handling, CSRF, CORS, security headers, GraphQL, WebSocket, WebRTC, or API endpoints. Applies to refactors and mechanical-looking field moves, not only to new features. Absence of security framing in the request is not evidence of absence of security relevance. Applies while the approach is still being chosen, not only once code exists. Retrieves the applicable OWASP Cheat Sheet guidance and ASVS requirements, and checks whether the codebase already has the control, before the code is written.
---

# Secure coding with OWASP guidance

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

The corpus gives you two things recall cannot: a **citable id** a reviewer can
check, and an **enumeration** of what the fix must address. Call the tools before
choosing the approach, not to confirm one you have already chosen -- a search run to
validate a decision does not surface what that decision already excluded.

## Process

1. **Name the data flow. Do not judge relevance.** For each field, config key, route or
   parameter the change touches, write one sentence saying where the value comes from,
   where it is stored, and what it is used to do. This is a factual description of the
   code and needs no security vocabulary — which is the point, because deciding whether a
   change "is security work" is the judgement that fails. A field move is a change.

2. **Probe the cheat sheets with those sentences.** Call `owasp_search` with
   `pack="cheatsheets"`, once per sentence. Cheat sheet titles and bodies are
   topic-shaped, so mundane wording reaches them — `api key supplied by an operator,
   stored in the database` returns `Symfony_Cheat_Sheet#sensitive-data` and
   `REST_Security_Cheat_Sheet#api-keys`, with no security vocabulary in the query at all.
   A noun plus its *type* reaches less: `base url for outbound http client` never
   reaches the SSRF sheet, at any depth the search returns, and reaches the
   unvalidated-redirect sheet only at rank 28 of 44 — past the default window entirely.
   What surfaces early instead, at rank 7, is
   `Ruby_on_Rails_Cheat_Sheet#redirects-and-forwards` — real redirect-validation advice,
   but framework-specific and incidental, not the general treatment. `url supplied by an
   operator, used to make a request from the server` instead puts
   `Unvalidated_Redirects_and_Forwards_Cheat_Sheet#dangerous-forward-example` at the top,
   whose `#validating-urls` section cross-references the SSRF cheat sheet's
   URL-validation guidance. Follow those cross-references. **Do not answer from memory**
   — recalled security advice is often a version out of date and carries no citation a
   reviewer can check. An empty result is cheap and is itself an answer.

3. **Narrow before fetching.** Cheat sheets reach 37,000 characters. Call `owasp_outline`
   on the best-matching `doc_key`, pick the relevant anchor, then `owasp_get` that section
   only.

4. **Cross to ASVS for the rule.** Cheat sheets describe implementation mistakes; ASVS
   states what is *required* at each level. Search `pack="asvs"` with the same data-flow
   sentence, then call `owasp_related(<req_id>, rel="guidance")` to confirm the sheet you
   read is the one mapped to that requirement. The reverse hop does not exist — passing a
   cheat sheet `doc_key` to `owasp_related` returns no edges — so do not read that
   emptiness as the corpus having no mapping.

5. **Establish precedence with the vocabulary the corpus just gave you.** Call `Grep` on
   the codebase for the control names the guidance named — allowlist, scheme, guard,
   connect, redirect, whatever it used — and not for names you thought of before reading.
   Then either extend the control that already exists or state why it does not fit. Do
   not write a validator, guard or middleware of your own before this step has run.

6. **Cite everything.** Every security claim carries its citation inline — `ASVS 5.0.0
   V6.2.1` or `Authentication_Cheat_Sheet#password-storage`. Get the exact version from
   `kb_info`.

7. **Write the code**, then state which requirements it satisfies and which it does not.

## If the knowledge base is unreachable

Say so explicitly and stop. Do not fall back on recalled guidance while appearing to have
consulted the knowledge base — that is worse than no guidance, because the citations are
missing and nobody can tell the difference until it matters.

## Notes

- Prefer L1 and L2 requirements unless the user states a higher target level.
- When guidance and existing codebase patterns conflict, surface the conflict rather than
  silently following either.

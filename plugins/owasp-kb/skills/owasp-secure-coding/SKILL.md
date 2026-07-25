---
name: owasp-secure-coding
description: >
  Use when writing or reviewing application code touching authentication,
  passwords, MFA, sessions, cookies, tokens, JWT, OAuth, OIDC, authorization,
  access control, input validation, SQL injection, command injection, XSS,
  output encoding, deserialization, file upload, file download, cryptography,
  TLS, key management, secrets, logging, error handling, CSRF, CORS, security
  headers, GraphQL, WebSocket, WebRTC, or API endpoints. Retrieves the
  applicable OWASP Cheat Sheet guidance and ASVS requirements before the code
  is written.
---

# Secure coding with OWASP guidance

Retrieve authoritative guidance before writing or approving security-relevant code.

## Process

1. **Search first.** Call `owasp_search` with the security topic in the code you are about
   to write or review. **Do not answer from memory** — recalled security advice is often a
   version out of date and carries no citation a reviewer can check.

2. **Narrow before fetching.** Cheat sheets reach 37,000 characters. Call `owasp_outline`
   on the best-matching `doc_key`, pick the relevant anchor, then `owasp_get` that section
   only.

3. **Find what is required, not just recommended.** For any ASVS requirement ids returned,
   call `owasp_related(<req_id>)` to reach the cheat sheet section describing how to satisfy
   it. Cheat sheets say what is advisable; ASVS says what is required at each level.

4. **Cite everything.** Every security claim carries its citation inline — `ASVS 5.0.0
   V6.2.1` or `Authentication_Cheat_Sheet#password-storage`. Get the exact version from
   `kb_info`.

5. **Write the code**, then state which requirements it satisfies and which it does not.

## If the knowledge base is unreachable

Say so explicitly and stop. Do not fall back on recalled guidance while appearing to have
consulted the knowledge base — that is worse than no guidance, because the citations are
missing and nobody can tell the difference until it matters.

## Notes

- Prefer L1 and L2 requirements unless the user states a higher target level.
- When guidance and existing codebase patterns conflict, surface the conflict rather than
  silently following either.

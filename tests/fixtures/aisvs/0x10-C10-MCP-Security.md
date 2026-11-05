# C10 Model Context Protocol (MCP) Security

## Control Objective

This chapter addresses secure discovery, authentication, authorization, transport, and use of MCP-based tool and resource integrations.

---

## C10.2 Authentication & Authorization

Callers must be authenticated and access to MCP servers authorized, following protocol best practices.

| # | Description | Level |
| :--: | --- | :---: |
| **10.2.1** | **Verify that** MCP servers validate access tokens for each request and do not rely on transport security alone. | 1 |
| **10.2.6** | Requirement removed. | |
| **10.2.10** | **Verify that** MCP servers enforce single use server-side for `requestState` that must be consumed at most once. | 2 |

---

## References

* [OWASP MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html)

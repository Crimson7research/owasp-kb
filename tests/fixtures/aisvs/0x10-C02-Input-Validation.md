# C2 Input Validation

## Control Objective

This chapter addresses validation of all inputs as a first-line defense against prompt injection, one of the most damaging attacks on AI systems.

---

## C2.1 Prompt Injection Defenses

Prompt injection is one of the top risks for AI systems, and defending against it requires a combination of pattern filters, data classifiers, and instruction hierarchy enforcement.

| # | Description | Level |
| :--------: | ------------------------------------------------------------------ | :---: |
| **2.1.1** | **Verify that** all external or derived inputs that may steer model behavior are treated as untrusted and screened by a prompt injection detection ruleset or classifier before being included in prompts or used to trigger actions. | 1 |
| **2.1.2** | **Verify that** the system enforces an instruction hierarchy in which system and developer messages override user instructions and other untrusted inputs. | 2 |

---

## C2.2 Content & Policy Screening

Inputs must be screened against content policy before they reach the model.

| # | Description | Level |
| :--: | --- | :---: |
| **2.2.1** | **Verify that** inputs are screened for policy violations using `allow-list` and classifier-based checks. | 3 |

---

## References

* [LLM Prompt Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html)
* [OWASP LLM Top 10](https://genai.owasp.org/llm-top-10/)

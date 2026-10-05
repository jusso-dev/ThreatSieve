# Threat model

## Assets and boundaries

Protect tenant telemetry, customer inventory, API credentials, raw intelligence, source licensing, classifier integrity and decision history. Public threat data is adversarial. Authentication sits in Hono before tenant API access. The Next.js route handler is a same-origin proxy; it never sends the server development key in a browser response.

| Threat | Control | Remaining boundary |
| --- | --- | --- |
| Tenant breakout | Tenant-bound private repository queries, observable visibility checks, scoped sessions and keys, isolation tests | New repository methods must preserve scope |
| SQL injection | Bound values and fixed internal table mappings | Migration code is trusted deployment code |
| XSS | React text rendering; no raw HTML descriptions; JSON served as data | Maintain this rule for report rendering |
| SSRF | Fixed public provider endpoints; no IoC fetches; redirects rejected; custom hosts require operator allowlisting | Operator-approved DNS must remain trustworthy |
| Prompt injection | Untrusted state, fixed typed schema, candidate validation, behavioural gates, conservative review | Models can still misjudge supplied evidence; evaluate adversarial cases |
| Credential theft | Random hashed API keys, HttpOnly SameSite sessions, expiration, revocation, no secrets in logs | Deploy behind HTTPS and protect bootstrap artifacts |
| CSRF | SameSite=Strict cookie and exact Origin verification on session mutations | API keys are bearer credentials |
| Upload abuse | Streaming byte limit, count limits, CSV record cap, no compressed archives, narrow STIX patterns | WAF/body limits should also apply at the edge |
| Poison feeds | Validation, bounded jobs, retry/DLQ, archived raw responses | Operators review rejected source data |
| Cost exhaustion | Tenant/key rate limits, daily classification budget and versioned cache | Add per-plan billing quotas and operational spend alerts |
| False attribution | Existing candidates only, unknown outcome, evidence dimensions and UI association labels | Analyst confirmation still needs a defensible process |
| Licensing leaks | Source redistributability metadata and filtered STIX evidence | Review commercial derivative-data rights |

Global graph writes originate from configured feeds. Customer telemetry stays in tenant tables. Analysts can confirm/reject within their tenant; they cannot silently rewrite global source intelligence.

Responses include request IDs. Logs contain allowlisted operational fields, not bodies, API tokens, report text or tenant asset names. The OpenCTI connector logs error classes rather than exception strings that might contain credentials.

The seed command is local-only and creates synthetic records plus a development key. Production deployment does not seed demo records or grant implicit access. The deployment pipeline separates reviewed database migration application from Worker deployment. No destructive migrations are shipped.

SSO, hardware-backed MFA, immutable external audit retention, WAF policies, incident alerting, tenant-specific retention and formal penetration testing are deployment/commercial hardening steps, not implicit guarantees from the codebase.

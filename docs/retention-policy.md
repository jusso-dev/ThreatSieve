# Retention policy decision

Status: **awaiting owner approval** (#27). No cleanup or R2 expiration is enabled.
The request to resolve issues does not specify legal retention periods, contractual
RPO/RTO or an approved deletion date. Those values must not be invented.

The owner must approve periods and recovery requirements for original intelligence,
source assertions, analyst/audit history, delivered events, completed pipeline jobs,
collection packages and original archives. Record jurisdiction, contractual
exceptions, holds, recovery windows and the approving owner/date alongside them.
Privacy and tenant deletion requests need a separate authenticated workflow.

Use `THREATSIEVE_WRANGLER_CONFIG=wrangler.staging.local.json pnpm exec tsx scripts/retention-inventory.ts --remote --before ISO_TIMESTAMP`
for aggregate history counts before an explicitly chosen cutoff. The report is
read-only and does not call old rows deletion candidates. It records active recovery
references and unfinished work. Select production configuration explicitly for its
inventory. Archive inventory and dependency tracing remain required before any R2
policy can be approved; R2 age alone does not establish that an archive is unused.

After approval, implement a bounded, audited cleanup with a dry-run/apply contract.
Protect unfinished jobs, undelivered outbox rows, active feed locks, descendant
correlations, versioned-ingestion delivery references and archives used by
recovery or exports. Completed bulk-page results remain dependencies until all
continuations finish. Never combine different tenants' eligibility or authorization.
Take a recovery bookmark, verify restore/audit behaviour and report deletion
counts and failures without publishing identifiers or private payloads.

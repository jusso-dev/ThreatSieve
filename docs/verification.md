# Verification record

The initial MVP was verified locally on 5 October 2026:

- 34 offline unit/integration tests pass, including real Miniflare D1 migrations, tenant isolation, feed alias resolution, queue reservation, chunk continuation, idempotency, bounded R2 multipart archives, candidate restrictions, prompt-injection policy, analyst overrides and STIX privacy.
- Two Chromium journeys pass: investigate evidence, inspect a graph node, confirm a decision, export STIX, source operations, inventory and mobile navigation.
- Strict TypeScript checks, ESLint, repository credential checks and production dependency audit pass. The dependency audit reports no known vulnerabilities at this verification time.
- The API Worker dry-run bundle, Next.js production build and OpenNext Cloudflare bundle build pass.
- A current official MITRE enterprise snapshot streams successfully: 26,086 objects from a roughly 54 MB response. This validates the streaming parser against the current upstream format; it is not a million-indicator throughput benchmark.
- A live Workers AI assessment of `example.com`, without supporting intelligence, invoked Clef-flash and escalated to Clef. The result remained unknown, requested analyst review, and contained no ATT&CK or actor mappings. This is an integration smoke test, not a model-quality evaluation.
- The Python `stix2` parser accepts the demonstration STIX bundle. The OpenCTI connector passes Python syntax compilation.

CI repeats offline validation, migrations, synthetic evaluation calculations, build, STIX parsing and browser tests. Its browser API omits AI and Vectorize bindings so tests cannot silently consume a live model. Seed data is explicitly synthetic, and recorded classifier responses exist only in test code.

Production infrastructure has not been provisioned by these checks. Live authenticated ThreatFox/URLhaus ingestion, target-account queue failure recovery, Vectorize indexing, representative classifier evaluation, sustained throughput and delivery into the operator's OpenCTI instance remain deployment acceptance checks in [deployment.md](deployment.md). No production deployment or commercial-readiness certification is implied.

## Follow-up verification — 6 October 2026

The UI/security correction release passes 42 offline unit/integration tests and seven Chromium journeys. Added coverage includes concurrent tenant-scoped bulk retries, pagination beyond 50 assessments, unresolved analyst queues, per-record export permissions, analyst metadata redaction, revised exports, stale and concurrent feedback, login Origin checks, tenant relationship rejection, private graph neighbors and adversarial candidate metadata.

Browser tests verify the full-document sidebar rail, mobile focus containment, native modal keyboard/Escape behavior, visible search failures, known-entity navigation without a classifier call, bulk retry keys, terminal polling and visible stale-feedback recovery. The repository screenshot has been updated from the running application.

Strict TypeScript, ESLint, credential checks, dependency audit, evaluation calculation checks, API Worker/Next.js/OpenNext builds and independent parsing of a benign analyst-corrected STIX bundle pass. These are regression and integration checks; the deployment acceptance limitations above still apply.

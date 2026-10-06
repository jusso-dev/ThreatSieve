# Accounts and team access

ThreatSieve uses Better Auth 1.7.7 with the organization plugin and the Drizzle D1 adapter. Users, organizations and memberships map directly onto the existing `users`, `tenants` and `tenant_members` tables. Intelligence and customer data keep their existing tenant IDs. Browser sessions are independent of integration API keys.

## First administrator

Provision a workspace using `pnpm exec tsx scripts/tenant.ts 'Organisation' admin@example.com --remote` with the deployment configuration selected as documented in [deployment](deployment.md). Open **Forgot password** on the sign-in page and enter that administrator email. The single-use reset link establishes a password for the existing account and verifies mailbox ownership. No default production password is created. Existing installations use this same flow after migrations 0006 and 0007.

Local bootstrap creates the explicitly synthetic account `analyst@example.test` with password `ThreatSieve local demo only!`, and generates a random local Better Auth secret. It never provisions this account remotely. The local demonstration still supports its development-only API credential. For an entirely isolated account/invitation demonstration with captured email instead of live delivery, run the full-stack tests.

## Invite a colleague

1. Open **Team & access**.
2. Enter the recipient's email and select their role.
3. Choose **Send invitation**. The recipient follows the email link, signs in or creates an account, verifies their email and accepts the invitation.
4. Invitations expire after 48 hours. Administrators can resend or cancel pending invitations.

An account alone grants no workspace access. A recipient must control the exact email on the invitation. Users belonging to multiple workspaces can switch on the team page. Public workspace creation and workspace deletion are disabled.

| Role    | Access                                                                     |
| ------- | -------------------------------------------------------------------------- |
| Admin   | Manage members, sources, environment, keys and assessments                 |
| Analyst | Read intelligence, submit assessments/imports and record analyst decisions |
| Viewer  | Read intelligence, sources and assessments                                 |

Every protected API request checks current membership and derives scopes from the current role. Removing a member immediately prevents workspace access. Removal or a role change also revokes API keys owned by that person in that workspace; regenerate necessary integration keys after a role change. Last-admin checks are enforced by Better Auth and atomic D1 triggers, including concurrent requests. Other tenants' memberships cannot be changed.

## Session and email security

- Eight-hour, HttpOnly, SameSite=Strict cookies; Secure on deployed environments. Session data is stored in D1, not browser storage. Cookie caching is disabled so revocation takes effect immediately.
- Passwords use Better Auth's scrypt hashing. New passwords must contain 12–128 characters. Password resets use single-use, one-hour email links and revoke all existing sessions.
- Verified email is required for sign-in and accepting invitations. Reset completion also verifies control of the mailbox.
- Same-origin web proxy forwards every Set-Cookie header and verification redirect. Auth POSTs and authenticated API mutations require the exact configured web Origin.
- Authentication rate limits use D1 and Cloudflare's connecting IP, with stricter limits for sign-in, registration, reset and invitations.
- Email bodies escape names and organization names. Tokens, passwords and message bodies are never logged by the application. Cloudflare Email Service uses the `EMAIL` binding and a verified sender.
- Delivery failure is surfaced as a retryable error; a persisted invitation can be resent. A successful send means provider acceptance, not guaranteed inbox delivery.
- Invitations, acceptance/rejection, member changes, sign-in, sign-out and workspace switches are recorded in tenant audit events.

Scoped, hashed API keys remain supported for automation and OpenCTI. The API-key-to-browser-session endpoint is disabled outside local development; old browser key sessions do not grant production access.

## Notifications

Sonner provides accessible, dismissible toasts for mutations, exports, import completion and request failures. Forms also retain inline errors and entered values. Permission errors explain how to get access; connection errors invite a retry; expired invitation/reset links explain how to recover. Read-only actions and repeated polling successes do not generate distracting notifications.

SSO and MFA are not enabled by this release.

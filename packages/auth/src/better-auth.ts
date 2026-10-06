import { betterAuth } from "better-auth/minimal";
import { organization } from "better-auth/plugins/organization";
import { APIError } from "better-auth/api";
import { drizzleAdapter } from "@better-auth/drizzle-adapter";
import { drizzle } from "drizzle-orm/d1";
import type { AppEnv } from "../../../apps/api/src/env";
import type { Principal, Scope } from "../../schemas/src/index";
import { AppError } from "../../observability/src/index";
import { ac, roles } from "./roles";
import * as schema from "./schema";

const escape = (value: string) =>
  value.replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ]!,
  );
export function createAuth(env: AppEnv, onEmailFailure?: () => void) {
  if (!env.BETTER_AUTH_SECRET || env.BETTER_AUTH_SECRET.length < 32)
    throw new AppError(
      "AUTH_UNAVAILABLE",
      503,
      "Sign-in is temporarily unavailable. Please try again shortly.",
    );
  const send = async (
    to: string,
    subject: string,
    description: string,
    url: string,
  ) => {
    try {
      await env.EMAIL.send({
        from: { email: env.AUTH_EMAIL_FROM, name: "ThreatSieve" },
        to,
        subject,
        text: `${description}\n\n${url}\n\nIf you did not request this, you can ignore this email.`,
        html: `<h1>ThreatSieve</h1><p>${escape(description)}</p><p><a href="${escape(url)}">Continue to ThreatSieve</a></p><p>If you did not request this, you can ignore this email.</p>`,
      });
    } catch {
      onEmailFailure?.();
      // Never log email bodies, verification links or provider errors containing recipient data.
      throw new APIError("SERVICE_UNAVAILABLE", {
        code: "EMAIL_UNAVAILABLE",
        message: "We couldn't send the email. Please try again shortly.",
      });
    }
  };
  return betterAuth({
    appName: "ThreatSieve",
    baseURL: env.WEB_ORIGIN,
    basePath: "/api/auth",
    secret: env.BETTER_AUTH_SECRET,
    logger: { disabled: true },
    trustedOrigins: [env.WEB_ORIGIN],
    database: drizzleAdapter(drizzle(env.DB), {
      provider: "sqlite",
      schema,
      transaction: false,
    }),
    disabledPaths: [
      "/organization/delete",
      "/organization/leave",
      "/organization/add-member",
    ],
    emailAndPassword: {
      enabled: true,
      minPasswordLength: 12,
      maxPasswordLength: 128,
      requireEmailVerification: true,
      revokeSessionsOnPasswordReset: true,
      sendResetPassword: async ({ user, url }) =>
        send(
          user.email,
          "Reset your ThreatSieve password",
          "Choose a new password for your ThreatSieve account. This link expires in one hour.",
          url,
        ),
      onPasswordReset: async ({ user }) => {
        // A successful single-use email reset proves control of the existing mailbox.
        await env.DB.prepare(
          "UPDATE users SET email_verified=1,updated_at=? WHERE id=?",
        )
          .bind(new Date().toISOString(), user.id)
          .run();
      },
    },
    emailVerification: {
      sendOnSignUp: true,
      sendOnSignIn: true,
      autoSignInAfterVerification: true,
      sendVerificationEmail: async ({ user, url }) =>
        send(
          user.email,
          "Verify your ThreatSieve email",
          "Verify your email address to securely join your ThreatSieve team. This link expires in one hour.",
          url,
        ),
    },
    session: {
      expiresIn: 8 * 60 * 60,
      updateAge: 60 * 60,
      cookieCache: { enabled: false },
    },
    rateLimit: {
      enabled: true,
      storage: "database",
      window: 60,
      max: 60,
      customRules: {
        "/sign-in/email": { window: 60, max: 5 },
        "/sign-up/email": { window: 60, max: 3 },
        "/request-password-reset": { window: 60, max: 3 },
        "/send-verification-email": { window: 60, max: 3 },
        "/organization/invite-member": { window: 60, max: 10 },
      },
    },
    advanced: {
      useSecureCookies: env.APP_ENV !== "development",
      defaultCookieAttributes: { httpOnly: true, sameSite: "strict" },
      ipAddress: { ipAddressHeaders: ["cf-connecting-ip"] },
    },
    databaseHooks: {
      session: {
        create: {
          before: async (session) => {
            const membership = await env.DB.prepare(
              "SELECT tenant_id FROM tenant_members WHERE user_id=? ORDER BY tenant_id LIMIT 1",
            )
              .bind(session.userId)
              .first<{ tenant_id: string }>();
            return {
              data: {
                ...session,
                activeOrganizationId: membership?.tenant_id ?? null,
              },
            };
          },
        },
      },
    },
    plugins: [
      organization({
        ac,
        roles,
        creatorRole: "admin",
        allowUserToCreateOrganization: false,
        requireEmailVerificationOnInvitation: true,
        invitationExpiresIn: 48 * 60 * 60,
        membershipLimit: 500,
        invitationLimit: 100,
        sendInvitationEmail: async (data) =>
          send(
            data.email,
            "You're invited to ThreatSieve",
            `${data.inviter.user.name} invited you to join ${data.organization.name} as ${data.role}. This invitation expires in 48 hours.`,
            `${env.WEB_ORIGIN}/accept-invitation?id=${encodeURIComponent(data.id)}`,
          ),
        organizationHooks: {
          beforeUpdateMemberRole: async ({ newRole }) => {
            if (!(newRole in roles))
              throw new APIError("BAD_REQUEST", {
                message: "Choose admin, analyst or viewer.",
              });
          },
          beforeCreateInvitation: async ({ invitation }) => {
            if (!(invitation.role in roles))
              throw new APIError("BAD_REQUEST", {
                message: "Choose admin, analyst or viewer.",
              });
          },
          afterUpdateMemberRole: async ({ member }) => {
            await env.DB.prepare(
              "UPDATE api_keys SET revoked_at=? WHERE tenant_id=? AND user_id=? AND revoked_at IS NULL",
            )
              .bind(
                new Date().toISOString(),
                member.organizationId,
                member.userId,
              )
              .run();
          },
          afterRemoveMember: async ({ member }) => {
            // Removing a person also revokes their integration keys for this workspace.
            await env.DB.prepare(
              "UPDATE api_keys SET revoked_at=? WHERE tenant_id=? AND user_id=? AND revoked_at IS NULL",
            )
              .bind(
                new Date().toISOString(),
                member.organizationId,
                member.userId,
              )
              .run();
          },
        },
      }),
    ],
  });
}
export const roleScopes: Record<string, Scope[]> = {
  admin: [
    "admin",
    "intel:read",
    "assessment:read",
    "assessment:write",
    "feeds:read",
    "feeds:write",
  ],
  analyst: ["intel:read", "assessment:read", "assessment:write", "feeds:read"],
  viewer: ["intel:read", "assessment:read", "feeds:read"],
};
export async function authenticateSession(
  env: AppEnv,
  request: Request,
): Promise<Principal> {
  if (!request.headers.get("cookie")?.includes("better-auth.session_token="))
    throw new AppError("UNAUTHORIZED", 401, "Please sign in to continue.");
  const session = await createAuth(env).api.getSession({
    headers: request.headers,
  });
  if (!session)
    throw new AppError("UNAUTHORIZED", 401, "Please sign in to continue.");
  const tenantId = session.session.activeOrganizationId;
  const member = tenantId
    ? await env.DB.prepare(
        "SELECT role FROM tenant_members WHERE tenant_id=? AND user_id=?",
      )
        .bind(tenantId, session.user.id)
        .first<{ role: string }>()
    : null;
  if (!member || !tenantId)
    throw new AppError(
      "WORKSPACE_REQUIRED",
      403,
      "Join a team or select a workspace to continue.",
    );
  return {
    tenantId,
    userId: session.user.id,
    keyId: session.session.id,
    kind: "session",
    scopes: roleScopes[member.role] ?? [],
  };
}

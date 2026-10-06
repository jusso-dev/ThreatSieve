"use client";
import { createAuthClient } from "better-auth/react";
import { organizationClient } from "better-auth/client/plugins";
import { toast } from "sonner";
import { ac, roles } from "../../../packages/auth/src/roles";
export const authClient = createAuthClient({
  plugins: [organizationClient({ ac, roles })],
});
const messages: Record<string, string> = {
  EMAIL_UNAVAILABLE:
    "We couldn’t send the email. Try again shortly. For a pending invitation, use Resend.",
  INVALID_EMAIL_OR_PASSWORD:
    "That email and password don’t match. Try again or reset your password.",
  EMAIL_NOT_VERIFIED:
    "Please verify your email first. Check your inbox for a new verification link.",
  USER_ALREADY_EXISTS:
    "An account with this email already exists. Sign in or reset your password.",
  USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL:
    "An account with this email already exists. Sign in or reset your password.",
  INVALID_TOKEN:
    "This link has expired or has already been used. Request a new email to continue.",
  TOKEN_EXPIRED: "This link has expired. Request a new email to continue.",
  INVITATION_NOT_FOUND:
    "This invitation is no longer available. Ask your team administrator for a new one.",
  INVITATION_EXPIRED:
    "This invitation has expired. Ask your team administrator to resend it.",
  YOU_ARE_NOT_THE_RECIPIENT_OF_THE_INVITATION:
    "Sign in with the email address this invitation was sent to.",
  YOU_CANNOT_LEAVE_THE_ORGANIZATION_WITHOUT_AN_OWNER:
    "Your team needs at least one admin. Promote another member first.",
  YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER:
    "Your team needs at least one admin. Promote another member first.",
  YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_MEMBER:
    "Only a team admin can change member roles.",
  TOO_MANY_REQUESTS:
    "You’ve made several attempts. Please wait a minute and try again.",
};
export async function authResult<T>(
  operation: Promise<{
    data: T;
    error: { message?: string; code?: string; status?: number } | null;
  }>,
  success?: string,
): Promise<NonNullable<T>> {
  try {
    const result = await operation;
    if (result.error)
      throw new Error(
        result.error.status === 429
          ? messages.TOO_MANY_REQUESTS
          : (messages[result.error.code ?? ""] ??
              (result.error.status && result.error.status >= 500
                ? "We couldn’t complete this request. Please try again shortly."
                : result.error.message ||
                  "We couldn’t complete this request. Please try again.")),
      );
    if (success) toast.success(success);
    return result.data as NonNullable<T>;
  } catch (error) {
    const message =
      error instanceof TypeError
        ? "Check your connection and try again."
        : error instanceof Error
          ? error.message
          : "Something went wrong. Please try again.";
    toast.error(message);
    throw new Error(message);
  }
}
export function invitationReturn(): string {
  const target = new URLSearchParams(window.location.search).get("returnTo");
  return target?.startsWith("/accept-invitation?id=") ? target : "/team";
}

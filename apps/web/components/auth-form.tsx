"use client";
import { toast } from "sonner";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { ShieldCheck, ArrowRight, MailCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { authClient, authResult, invitationReturn } from "@/lib/auth";
type Mode = "sign-in" | "sign-up" | "forgot-password" | "reset-password";
const headings: Record<Mode, string> = {
  "sign-in": "Welcome to your workspace.",
  "sign-up": "Join your team.",
  "forgot-password": "Let’s get you back in.",
  "reset-password": "Choose a new password.",
};
export function AuthForm({ mode }: { mode: Mode }) {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [sent, setSent] = useState(false);
  const [returnTo, setReturnTo] = useState("/team");
  const [token, setToken] = useState("");
  useEffect(() => {
    setReturnTo(invitationReturn());
    const query = new URLSearchParams(window.location.search);
    setToken(query.get("token") ?? "");
    if (query.has("error"))
      setError(
        "This link is invalid or has expired. Request a new email to continue.",
      );
  }, []);
  const link = (path: string) =>
    path + "?returnTo=" + encodeURIComponent(returnTo);
  return (
    <main className="sign-in">
      <section className="sign-in-card">
        <Link className="brand" href="/sign-in">
          <ShieldCheck size={26} />
          ThreatSieve<span className="brand-period">.</span>
        </Link>
        <div className="eyebrow">YOUR TEAM. YOUR INTELLIGENCE.</div>
        <h1>{sent ? "Check your inbox." : headings[mode]}</h1>
        <p>
          {sent
            ? mode === "sign-up"
              ? "Verify your email using the link we sent, then accept your team invitation."
              : "If an account exists for this address, we’ve sent a password-reset link. Check your spam folder too."
            : mode === "forgot-password"
              ? "Enter your work email and we’ll send you a secure reset link."
              : "Evidence-backed decisions start with a secure workspace."}
        </p>
        {sent ? (
          <div className="auth-sent">
            <MailCheck size={36} />
            <Link className="text-link" href={link("/sign-in")}>
              Return to sign in
            </Link>
          </div>
        ) : (
          <form
            onSubmit={async (e) => {
              e.preventDefault();
              setError("");
              if (
                (mode === "sign-up" || mode === "reset-password") &&
                password !== confirm
              ) {
                setError(
                  "Your passwords don’t match. Please enter them again.",
                );
                toast.error(
                  "Your passwords don’t match. Please enter them again.",
                );
                return;
              }
              setBusy(true);
              try {
                if (mode === "sign-in") {
                  await authResult(
                    authClient.signIn.email({
                      email,
                      password,
                      callbackURL: window.location.origin + returnTo,
                    }),
                    "Welcome back. You’re signed in.",
                  );
                  router.push(returnTo);
                }
                if (mode === "sign-up") {
                  await authResult(
                    authClient.signUp.email({
                      email,
                      password,
                      name,
                      callbackURL: window.location.origin + returnTo,
                    }),
                    "Account created. Check your email to verify it.",
                  );
                  setSent(true);
                  setPassword("");
                  setConfirm("");
                }
                if (mode === "forgot-password") {
                  await authResult(
                    authClient.requestPasswordReset({
                      email,
                      redirectTo: window.location.origin + "/reset-password",
                    }),
                    "If an account exists, a reset link is on its way.",
                  );
                  setSent(true);
                }
                if (mode === "reset-password") {
                  await authResult(
                    authClient.resetPassword({ newPassword: password, token }),
                    "Password updated. Sign in with your new password.",
                  );
                  router.push(link("/sign-in"));
                }
              } catch (e) {
                setError(e instanceof Error ? e.message : "Please try again.");
              } finally {
                setBusy(false);
              }
            }}
          >
            {mode === "sign-up" && (
              <>
                <label htmlFor="name">Your name</label>
                <input
                  id="name"
                  autoComplete="name"
                  maxLength={100}
                  required
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                />
              </>
            )}
            {mode !== "reset-password" && (
              <>
                <label htmlFor="email">Work email</label>
                <input
                  id="email"
                  type="email"
                  autoComplete="email"
                  maxLength={254}
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                />
              </>
            )}
            {mode !== "forgot-password" && (
              <>
                <label htmlFor="password">
                  {mode === "reset-password" ? "New password" : "Password"}
                </label>
                <input
                  id="password"
                  type="password"
                  autoComplete={
                    mode === "sign-in" ? "current-password" : "new-password"
                  }
                  minLength={mode === "sign-in" ? 1 : 12}
                  maxLength={128}
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                />
              </>
            )}
            {(mode === "sign-up" || mode === "reset-password") && (
              <>
                <p className="field-help">
                  Use 12–128 characters. A unique passphrase works well.
                </p>
                <label htmlFor="confirm-password">Confirm password</label>
                <input
                  id="confirm-password"
                  type="password"
                  autoComplete="new-password"
                  minLength={12}
                  maxLength={128}
                  required
                  value={confirm}
                  onChange={(e) => setConfirm(e.target.value)}
                />
              </>
            )}
            {error && (
              <p className="form-error" role="alert">
                {error}
              </p>
            )}
            <Button disabled={busy || (mode === "reset-password" && !token)}>
              {busy
                ? "Please wait…"
                : mode === "sign-in"
                  ? "Sign in"
                  : mode === "sign-up"
                    ? "Create account"
                    : mode === "forgot-password"
                      ? "Send reset link"
                      : "Save new password"}
              <ArrowRight size={15} />
            </Button>
          </form>
        )}
        <div className="auth-links">
          {mode === "sign-in" ? (
            <>
              <Link href={link("/forgot-password")}>Forgot password?</Link>
              <Link href={link("/sign-up")}>Create an account</Link>
            </>
          ) : (
            <Link href={link("/sign-in")}>Back to sign in</Link>
          )}
        </div>
        <p className="sign-in-note">
          {mode === "sign-up"
            ? "An account does not grant workspace access. Your team administrator must invite you."
            : "Individual accounts. Secure sessions. Access controlled by your team."}
        </p>
      </section>
    </main>
  );
}

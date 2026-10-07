"use client";
import { useState } from "react";
import { authClient, authResult } from "@/lib/auth";
import { PageHeader } from "@/components/shell";
import { Button } from "@/components/ui/button";

export default function SecurityPage() {
  const { data: session, isPending, refetch } = authClient.useSession();
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [setup, setSetup] = useState<{
    totpURI: string;
    backupCodes: string[];
  } | null>(null);
  const [codes, setCodes] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const enabled = session?.user.twoFactorEnabled === true;
  async function run(work: () => Promise<void>) {
    setBusy(true);
    setError("");
    try {
      await work();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Please try again.");
    } finally {
      setBusy(false);
      setPassword("");
    }
  }
  return (
    <>
      <PageHeader
        title="Account security"
        description="Protect your account with an authenticator app and single-use recovery codes."
      />
      <section className="panel team-invite-panel">
        <h2>Two-factor authentication</h2>
        <p role="status">
          {isPending
            ? "Loading account security…"
            : enabled
              ? "Enabled — your password and a second factor are required to sign in."
              : "Not enabled — add an authenticator to protect your account."}
        </p>
        {setup ? (
          <form
            className="team-invite-form"
            onSubmit={(e) => {
              e.preventDefault();
              void run(async () => {
                await authResult(
                  authClient.twoFactor.verifyTotp({ code, trustDevice: false }),
                  "Two-factor authentication enabled.",
                );
                await authResult(
                  authClient.revokeOtherSessions(),
                  "Other sessions signed out.",
                );
                setCodes(setup.backupCodes);
                setSetup(null);
                setCode("");
                await refetch();
              });
            }}
          >
            <div>
              <p>
                In your authenticator, add a time-based account named
                ThreatSieve and enter this setup key. Keep it private.
              </p>
              <label htmlFor="setup-key">Authenticator setup key</label>
              <input
                id="setup-key"
                readOnly
                value={new URL(setup.totpURI).searchParams.get("secret") ?? ""}
                autoComplete="off"
              />
              <label htmlFor="confirmation-code">Authenticator code</label>
              <input
                id="confirmation-code"
                autoComplete="one-time-code"
                inputMode="numeric"
                pattern="[0-9]{6}"
                maxLength={6}
                required
                value={code}
                onChange={(e) => setCode(e.target.value.trim())}
              />
            </div>
            <Button disabled={busy}>Verify authenticator</Button>
            <Button
              type="button"
              variant="ghost"
              disabled={busy}
              onClick={() => {
                setSetup(null);
                setCode("");
              }}
            >
              Cancel setup
            </Button>
          </form>
        ) : (
          <form
            className="team-invite-form"
            onSubmit={(e) => {
              e.preventDefault();
              void run(async () => {
                if (enabled) {
                  const result = await authResult(
                    authClient.twoFactor.generateBackupCodes({ password }),
                    "New recovery codes created. Previous codes no longer work.",
                  );
                  setCodes(result.backupCodes);
                } else {
                  const result = await authResult(
                    authClient.twoFactor.enable({ password }),
                    "Setup started. Verify a code to finish enabling protection.",
                  );
                  if (result.method === "totp")
                    setSetup({
                      totpURI: result.totpURI,
                      backupCodes: result.backupCodes,
                    });
                }
              });
            }}
          >
            <div>
              <label htmlFor="security-password">Current password</label>
              <input
                id="security-password"
                type="password"
                autoComplete="current-password"
                required
                maxLength={128}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </div>
            <Button disabled={busy || isPending}>
              {enabled ? "Replace recovery codes" : "Set up authenticator"}
            </Button>
            {enabled && (
              <Button
                type="button"
                variant="outline"
                disabled={busy || !password}
                onClick={() =>
                  void run(async () => {
                    await authResult(
                      authClient.twoFactor.disable({ password }),
                      "Two-factor authentication disabled.",
                    );
                    setCodes([]);
                    await refetch();
                  })
                }
              >
                Disable two-factor authentication
              </Button>
            )}
          </form>
        )}
        {error && (
          <p role="alert" className="form-error">
            {error}
          </p>
        )}
        {codes.length > 0 && (
          <section aria-label="Recovery codes">
            <h3>Save your recovery codes</h3>
            <p>
              Store these in your password manager. Each code works once.
              Closing this page clears this display.
            </p>
            <pre style={{ whiteSpace: "pre-wrap" }}>{codes.join("\n")}</pre>
            <Button variant="outline" onClick={() => setCodes([])}>
              I have saved my recovery codes
            </Button>
          </section>
        )}
      </section>
      <section className="panel team-invite-panel">
        <h2>Other sessions</h2>
        <p>
          Sign out browsers on other devices. Your current session stays active.
        </p>
        <Button
          variant="outline"
          disabled={busy || isPending}
          onClick={() =>
            void run(async () => {
              await authResult(
                authClient.revokeOtherSessions(),
                "Other sessions signed out.",
              );
            })
          }
        >
          Sign out other sessions
        </Button>
      </section>
    </>
  );
}

"use client";
import Link from "next/link";
import { useEffect, useState } from "react";
import { ShieldCheck, Users } from "lucide-react";
import { authClient, authResult } from "@/lib/auth";
import { Button } from "@/components/ui/button";
export default function AcceptInvitation() {
  const { data: session, isPending } = authClient.useSession();
  const [id, setId] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [invite, setInvite] = useState<{
    organizationName: string;
    email: string;
    role: string;
    status: string;
    expiresAt: Date | string;
  } | null>(null);
  useEffect(() => {
    setId(new URLSearchParams(window.location.search).get("id") ?? "");
  }, []);
  useEffect(() => {
    if (session && id)
      void authResult(authClient.organization.getInvitation({ query: { id } }))
        .then(setInvite)
        .catch((e) => setError(e.message));
  }, [session, id]);
  const returnTo = "/accept-invitation?id=" + encodeURIComponent(id);
  return (
    <main className="sign-in">
      <section className="sign-in-card">
        <Link href="/sign-in" className="brand">
          <ShieldCheck />
          ThreatSieve.
        </Link>
        <Users size={32} />
        <h1>You’re invited.</h1>
        {isPending ? (
          <p role="status">Checking your account…</p>
        ) : !session ? (
          <>
            <p>
              Sign in or create an account using the email address your
              invitation was sent to.
            </p>
            <div className="auth-links">
              <Link
                className="button button-primary"
                href={"/sign-in?returnTo=" + encodeURIComponent(returnTo)}
              >
                Sign in to join
              </Link>
              <Link
                className="text-link"
                href={"/sign-up?returnTo=" + encodeURIComponent(returnTo)}
              >
                Create an account
              </Link>
            </div>
          </>
        ) : (
          <>
            <p>
              Signed in as <strong>{session.user.email}</strong>.
            </p>
            {invite && (
              <>
                <h2>{invite.organizationName}</h2>
                <p>
                  Join this workspace as <strong>{invite.role}</strong>. Your
                  access applies only to this team.
                </p>
                {invite.status === "pending" &&
                new Date(invite.expiresAt) > new Date() ? (
                  <div className="auth-links">
                    <Button
                      disabled={busy}
                      onClick={async () => {
                        setBusy(true);
                        setError("");
                        try {
                          const result = await authResult(
                            authClient.organization.acceptInvitation({
                              invitationId: id,
                            }),
                            "You’ve joined the team. Welcome aboard.",
                          );
                          await authResult(
                            authClient.organization.setActive({
                              organizationId: result.member.organizationId,
                            }),
                          );
                          window.location.assign("/");
                        } catch (e) {
                          setError(
                            e instanceof Error
                              ? e.message
                              : "Please try again.",
                          );
                        } finally {
                          setBusy(false);
                        }
                      }}
                    >
                      {busy ? "Joining…" : "Accept invitation"}
                    </Button>
                    <Button
                      variant="ghost"
                      disabled={busy}
                      onClick={async () => {
                        setBusy(true);
                        try {
                          await authResult(
                            authClient.organization.rejectInvitation({
                              invitationId: id,
                            }),
                            "Invitation declined.",
                          );
                          window.location.assign("/team");
                        } catch (e) {
                          setError(
                            e instanceof Error
                              ? e.message
                              : "Please try again.",
                          );
                        } finally {
                          setBusy(false);
                        }
                      }}
                    >
                      Decline
                    </Button>
                  </div>
                ) : (
                  <p role="status">
                    This invitation has expired or has already been used. Ask
                    your administrator for a new invitation.
                  </p>
                )}
              </>
            )}
            <Button
              variant="ghost"
              disabled={busy}
              onClick={() =>
                void authResult(authClient.signOut())
                  .then(() => window.location.reload())
                  .catch(() => {})
              }
            >
              Use a different account
            </Button>
          </>
        )}
        {error && (
          <p className="form-error" role="alert">
            {error}
          </p>
        )}
        {!id && (
          <p className="form-error" role="alert">
            The invitation link is incomplete. Open the full link from your
            email.
          </p>
        )}
      </section>
    </main>
  );
}

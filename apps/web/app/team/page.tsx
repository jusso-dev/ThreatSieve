"use client";
import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { Users, UserPlus, ShieldCheck, Mail } from "lucide-react";
import { authClient, authResult } from "@/lib/auth";
import { PageHeader } from "@/components/shell";
import { Modal } from "@/components/ui/modal";
import { Button } from "@/components/ui/button";
type Role = "admin" | "analyst" | "viewer";
type Member = {
  id: string;
  userId: string;
  role: string;
  user: { name: string; email: string };
};
type Invitation = {
  id: string;
  email: string;
  role: string;
  status: string;
  expiresAt: Date | string;
};
type Team = {
  id: string;
  name: string;
  members: Member[];
  invitations: Invitation[];
};
export default function TeamPage() {
  const { data: session, isPending } = authClient.useSession();
  const [team, setTeam] = useState<Team | null>(null);
  const [teams, setTeams] = useState<{ id: string; name: string }[]>([]);
  const [invitations, setInvitations] = useState<
    { id: string; organizationName: string }[]
  >([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<Role>("analyst");
  const [busy, setBusy] = useState("");
  const [removal, setRemoval] = useState<Member | null>(null);
  const load = useCallback(async () => {
    setError("");
    try {
      const orgs = await authResult(authClient.organization.list());
      setTeams(orgs);
      const invites = await authResult(
        authClient.organization.listUserInvitations(),
      );
      setInvitations(
        invites.filter(
          (i) => i.status === "pending" && new Date(i.expiresAt) > new Date(),
        ),
      );
      const active = await authResult(
        authClient.organization.getFullOrganization({
          query: { membersLimit: 500 },
        }),
      );
      setTeam(active as Team | null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "We couldn’t load your team.");
    } finally {
      setLoading(false);
    }
  }, []);
  useEffect(() => {
    if (session) void load();
    else if (!isPending) window.location.assign("/sign-in");
  }, [session, isPending, load]);
  const me = team?.members.find((m) => m.userId === session?.user.id);
  const admin = me?.role === "admin";
  const change = async (id: string, operation: () => Promise<unknown>) => {
    setBusy(id);
    setError("");
    try {
      await operation();
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Please try again.");
    } finally {
      setBusy("");
    }
  };
  return (
    <>
      <PageHeader
        eyebrow="WORKSPACE ACCESS"
        title="Your team"
        description="Invite the people you trust. Give each person the access they need."
      />
      {error && (
        <div className="form-error" role="alert">
          {error}
          <Button variant="ghost" onClick={() => void load()}>
            Try again
          </Button>
        </div>
      )}
      {loading ? (
        <div className="state-panel" role="status">
          Loading your team…
        </div>
      ) : (
        <>
          {teams.length > 0 && (
            <section className="team-workspace panel">
              <div>
                <span className="eyebrow">ACTIVE WORKSPACE</span>
                <h2>
                  <ShieldCheck size={19} />
                  {team?.name ?? "Choose your workspace"}
                </h2>
              </div>
              <label>
                Switch workspace
                <select
                  aria-label="Switch workspace"
                  value={team?.id ?? ""}
                  disabled={!!busy}
                  onChange={(e) =>
                    void change("switch", async () => {
                      await authResult(
                        authClient.organization.setActive({
                          organizationId: e.target.value,
                        }),
                        "Workspace switched.",
                      );
                      window.location.assign("/team");
                    })
                  }
                >
                  <option value="" disabled>
                    Select a workspace
                  </option>
                  {teams.map((t) => (
                    <option key={t.id} value={t.id}>
                      {t.name}
                    </option>
                  ))}
                </select>
              </label>
            </section>
          )}
          {invitations.length > 0 && (
            <section className="panel team-invitations">
              <h2>
                <Mail size={18} />
                Invitations for you
              </h2>
              {invitations.map((i) => (
                <div className="team-invite-row" key={i.id}>
                  <span>{i.organizationName}</span>
                  <Link
                    className="text-link"
                    href={"/accept-invitation?id=" + encodeURIComponent(i.id)}
                  >
                    Review invitation →
                  </Link>
                </div>
              ))}
            </section>
          )}
          {!team && (
            <section className="state-panel">
              <Users size={32} />
              <h2>Your workspace is one invitation away.</h2>
              <p>
                Ask your team administrator to invite{" "}
                <strong>{session?.user.email}</strong>. Your invitations will
                appear here.
              </p>
              <Button variant="outline" onClick={() => void load()}>
                Check for invitations
              </Button>
            </section>
          )}
          {team && (
            <>
              <section className="team-role-guide">
                <div>
                  <strong>Admin</strong>
                  <p>Manages members, sources, environment and API access.</p>
                </div>
                <div>
                  <strong>Analyst</strong>
                  <p>Investigates threats and records analyst decisions.</p>
                </div>
                <div>
                  <strong>Viewer</strong>
                  <p>
                    Reads intelligence and assessments without making changes.
                  </p>
                </div>
              </section>
              {admin && (
                <section className="panel team-invite-panel">
                  <h2>
                    <UserPlus size={18} />
                    Invite a team member
                  </h2>
                  <p className="panel-subtitle">
                    They’ll receive a secure invitation by email. Invitations
                    expire after 48 hours.
                  </p>
                  <form
                    className="team-invite-form"
                    onSubmit={(e) => {
                      e.preventDefault();
                      void change("invite", async () => {
                        await authResult(
                          authClient.organization.inviteMember({
                            email,
                            role,
                            organizationId: team.id,
                          }),
                          "Invitation sent. Your teammate can join from their email.",
                        );
                        setEmail("");
                      });
                    }}
                  >
                    <div>
                      <label htmlFor="invite-email">Work email</label>
                      <input
                        id="invite-email"
                        type="email"
                        required
                        maxLength={254}
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
                        placeholder="colleague@company.com"
                      />
                    </div>
                    <div>
                      <label htmlFor="invite-role">Role</label>
                      <select
                        id="invite-role"
                        value={role}
                        onChange={(e) => setRole(e.target.value as Role)}
                      >
                        <option value="viewer">Viewer</option>
                        <option value="analyst">Analyst</option>
                        <option value="admin">Admin</option>
                      </select>
                    </div>
                    <Button disabled={!!busy}>
                      <UserPlus size={16} />
                      {busy === "invite" ? "Sending…" : "Send invitation"}
                    </Button>
                  </form>
                </section>
              )}
              <section className="panel team-members">
                <h2>
                  <Users size={18} />
                  Members <span className="muted">{team.members.length}</span>
                </h2>
                <div className="table-scroll">
                  <table>
                    <thead>
                      <tr>
                        <th>Member</th>
                        <th>Role</th>
                        <th>Access</th>
                      </tr>
                    </thead>
                    <tbody>
                      {team.members.map((member) => (
                        <tr key={member.id}>
                          <td>
                            <strong>
                              {member.user.name}
                              {member.userId === session?.user.id
                                ? " (you)"
                                : ""}
                            </strong>
                            <small>{member.user.email}</small>
                          </td>
                          <td>
                            {admin ? (
                              <select
                                aria-label={"Role for " + member.user.email}
                                value={member.role}
                                disabled={!!busy}
                                onChange={(e) =>
                                  void change(member.id, () =>
                                    authResult(
                                      authClient.organization.updateMemberRole({
                                        memberId: member.id,
                                        organizationId: team.id,
                                        role: e.target.value as Role,
                                      }),
                                      "Role updated. Any API keys issued to this member were revoked.",
                                    ),
                                  )
                                }
                              >
                                <option value="viewer">Viewer</option>
                                <option value="analyst">Analyst</option>
                                <option value="admin">Admin</option>
                              </select>
                            ) : (
                              <span className="role-label">{member.role}</span>
                            )}
                          </td>
                          <td>
                            {admin && (
                              <Button
                                size="sm"
                                variant="ghost"
                                disabled={!!busy}
                                onClick={() => setRemoval(member)}
                              >
                                Remove
                              </Button>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </section>
              {admin && (
                <section className="panel team-invitations">
                  <h2>
                    <Mail size={18} />
                    Pending invitations
                  </h2>
                  {team.invitations.filter((i) => i.status === "pending")
                    .length === 0 ? (
                    <p className="panel-subtitle">
                      All caught up. There are no pending invitations.
                    </p>
                  ) : (
                    team.invitations
                      .filter((i) => i.status === "pending")
                      .map((i) => (
                        <div className="team-invite-row" key={i.id}>
                          <div>
                            <strong>{i.email}</strong>
                            <small>
                              {i.role} ·{" "}
                              {new Date(i.expiresAt) < new Date()
                                ? "Expired"
                                : "Expires " +
                                  new Date(i.expiresAt).toLocaleDateString()}
                            </small>
                          </div>
                          <div className="team-actions">
                            <Button
                              size="sm"
                              variant="outline"
                              disabled={!!busy}
                              onClick={() =>
                                void change(i.id, () =>
                                  authResult(
                                    authClient.organization.inviteMember({
                                      email: i.email,
                                      role: i.role as Role,
                                      organizationId: team.id,
                                      resend: true,
                                    }),
                                    "Invitation sent again.",
                                  ),
                                )
                              }
                            >
                              Resend
                            </Button>
                            <Button
                              size="sm"
                              variant="ghost"
                              disabled={!!busy}
                              onClick={() =>
                                void change(i.id, () =>
                                  authResult(
                                    authClient.organization.cancelInvitation({
                                      invitationId: i.id,
                                    }),
                                    "Invitation canceled. The old link will no longer work.",
                                  ),
                                )
                              }
                            >
                              Cancel invitation
                            </Button>
                          </div>
                        </div>
                      ))
                  )}
                </section>
              )}
            </>
          )}
        </>
      )}
      {removal && (
        <Modal
          titleId="remove-title"
          busy={!!busy}
          onClose={() => setRemoval(null)}
        >
          <h2 id="remove-title">Remove {removal.user.name}?</h2>
          <p>
            They will lose access to this workspace immediately. Their workspace
            API keys will also be revoked.
          </p>
          <div className="modal-actions">
            <Button
              autoFocus
              variant="outline"
              disabled={!!busy}
              onClick={() => setRemoval(null)}
            >
              Keep member
            </Button>
            <Button
              variant="destructive"
              disabled={!!busy}
              onClick={() =>
                void change("remove", async () => {
                  await authResult(
                    authClient.organization.removeMember({
                      memberIdOrEmail: removal.id,
                      organizationId: team!.id,
                    }),
                    "Member removed. Workspace access has been revoked.",
                  );
                  setRemoval(null);
                })
              }
            >
              Remove member
            </Button>
          </div>
        </Modal>
      )}
    </>
  );
}

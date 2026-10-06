"use client";
import { useApi } from "@/lib/api";
import { Button } from "./ui/button";
type Action = { type: string; target?: string };
export function PlaybookActions({
  actions,
  onChange,
}: {
  actions: Action[];
  onChange: (actions: Action[]) => void;
}) {
  const watchlists = useApi<{ data: { id: string; title: string }[] }>(
    "v1/watchlists?limit=100",
  );
  const collections = useApi<{
    data: { id: string; title: string; publication: string }[];
  }>("v1/collections?status=published&limit=100");
  const integrations = useApi<{ data: { id: string; name: string }[] }>(
    "v1/integrations",
  );
  const change = (i: number, a: Action) =>
    onChange(actions.map((v, index) => (i === index ? a : v)));
  return (
    <fieldset>
      <legend>Actions</legend>
      <p className="muted">
        Executed in order. Integrations are queued and retain their own delivery
        status.
      </p>
      {actions.map((a, i) => {
        const choices =
          a.type === "add-to-watchlist"
            ? watchlists.data?.data.map((w) => ({ id: w.id, name: w.title }))
            : a.type === "publish-taxii"
              ? collections.data?.data
                  .filter((c) => c.publication === "taxii")
                  .map((c) => ({ id: c.id, name: c.title }))
              : a.type === "send-webhook"
                ? integrations.data?.data
                : undefined;
        return (
          <div className="playbook-action" key={i}>
            <label>
              Action {i + 1}
              <select
                value={a.type}
                onChange={(e) => change(i, { type: e.target.value })}
              >
                {[
                  "notify",
                  "tag",
                  "add-to-watchlist",
                  "create-investigation",
                  "enrich",
                  "export",
                  "publish-taxii",
                  "send-webhook",
                ].map((t) => (
                  <option key={t}>{t}</option>
                ))}
              </select>
            </label>
            {["add-to-watchlist", "publish-taxii", "send-webhook"].includes(
              a.type,
            ) ? (
              <label>
                Destination
                <select
                  required
                  value={a.target ?? ""}
                  onChange={(e) => change(i, { ...a, target: e.target.value })}
                >
                  <option value="">Select a destination</option>
                  {choices?.map((c) => (
                    <option key={c.id} value={c.id}>
                      {c.name}
                    </option>
                  ))}
                </select>
                {!choices?.length && (
                  <small>
                    No eligible destinations are configured for this workspace.
                  </small>
                )}
              </label>
            ) : ["tag", "create-investigation"].includes(a.type) ? (
              <label>
                {a.type === "tag" ? "Tag" : "Investigation title"}
                <input
                  required={a.type === "tag"}
                  maxLength={200}
                  value={a.target ?? ""}
                  onChange={(e) => change(i, { ...a, target: e.target.value })}
                />
              </label>
            ) : (
              <p className="muted">
                {a.type === "export"
                  ? "Queue the latest assessment for STIX export and the existing OpenCTI connector."
                  : a.type === "enrich"
                    ? "Refresh graph and semantic context using the existing enrichment pipeline."
                    : "Notify this workspace when the trigger and conditions match."}
              </p>
            )}
            <Button
              type="button"
              variant="ghost"
              size="sm"
              disabled={actions.length === 1}
              onClick={() =>
                onChange(actions.filter((_, index) => index !== i))
              }
            >
              Remove action
            </Button>
          </div>
        );
      })}
      <Button
        type="button"
        variant="outline"
        disabled={actions.length >= 5}
        onClick={() => onChange([...actions, { type: "notify" }])}
      >
        Add action
      </Button>
    </fieldset>
  );
}

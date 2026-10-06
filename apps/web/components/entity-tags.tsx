"use client";
import { useState } from "react";
import { api } from "@/lib/api";
import { usePermission } from "@/lib/access";
import { Button } from "./ui/button";
export function EntityTags({
  id,
  tags,
  reload,
}: {
  id: string;
  tags: string[];
  reload: () => Promise<void>;
}) {
  const canWrite = usePermission("assessment:write"),
    [tag, setTag] = useState(""),
    [busy, setBusy] = useState(false);
  const update = async (value: string, operation: "add" | "remove") => {
    setBusy(true);
    try {
      await api("v1/entities/" + id + "/tags", {
        method: "POST",
        body: JSON.stringify({
          tag: value,
          operation,
          reason:
            operation === "add"
              ? "Tagged from intelligence dossier"
              : "Removed from intelligence dossier",
        }),
      });
      if (operation === "add") setTag("");
      await reload();
    } catch {
      /* API error toast retains the draft. */
    } finally {
      setBusy(false);
    }
  };
  return (
    <section className="work-section">
      <h2>Workspace tags</h2>
      <div className="actions">
        {tags.map((t) => (
          <span className="entity-tag" key={t}>
            {t}
            {canWrite && (
              <button
                disabled={busy}
                aria-label={"Remove tag " + t}
                onClick={() => void update(t, "remove")}
              >
                ×
              </button>
            )}
          </span>
        ))}
      </div>
      {!tags.length && <p className="muted">No workspace tags.</p>}
      {canWrite && (
        <form
          className="inline-form"
          onSubmit={(e) => {
            e.preventDefault();
            void update(tag, "add");
          }}
        >
          <input
            aria-label="Add workspace tag"
            value={tag}
            maxLength={100}
            onChange={(e) => setTag(e.target.value)}
          />
          <Button variant="outline" disabled={busy || !tag.trim()}>
            Add tag
          </Button>
        </form>
      )}
    </section>
  );
}

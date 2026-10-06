"use client";
import { useState } from "react";
import { BookmarkPlus, Trash2 } from "lucide-react";
import { api, useApi } from "@/lib/api";
import { Button } from "./ui/button";
import { Modal } from "./ui/modal";
import type { AssessmentFilters } from "../../../packages/schemas/src/query";

export function SavedViews({
  filters,
  onApply,
}: {
  filters: AssessmentFilters;
  onApply: (filters: AssessmentFilters) => void;
}) {
  const { data, reload } = useApi<{
    data: { id: string; name: string; filters: AssessmentFilters }[];
  }>("v1/saved-views");
  const [open, setOpen] = useState(false),
    [name, setName] = useState(""),
    [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  const [selected, setSelected] = useState("");
  return (
    <>
      <div className="saved-view-controls">
        <label className="sr-only" htmlFor="saved-view">
          Saved triage views
        </label>
        <select
          id="saved-view"
          value={selected}
          onChange={(e) => {
            setSelected(e.target.value);
            const view = data?.data.find((v) => v.id === e.target.value);
            if (view) onApply(view.filters);
          }}
        >
          <option value="">Your saved views</option>
          {data?.data.map((v) => (
            <option key={v.id} value={v.id}>
              {v.name}
            </option>
          ))}
        </select>
        {selected && (
          <Button
            size="sm"
            variant="ghost"
            aria-label="Delete saved view"
            disabled={busy}
            onClick={async () => {
              setBusy(true);
              try {
                await api("v1/saved-views/" + selected, { method: "DELETE" });
                setSelected("");
                await reload();
              } catch {
                // The API helper displays the actionable error.
              } finally {
                setBusy(false);
              }
            }}
          >
            <Trash2 size={14} />
          </Button>
        )}
        <Button
          size="sm"
          variant="outline"
          onClick={() => {
            setName("");
            setError("");
            setOpen(true);
          }}
        >
          <BookmarkPlus size={14} />
          Save view
        </Button>
      </div>
      {open && (
        <Modal
          titleId="save-view-title"
          onClose={() => setOpen(false)}
          busy={busy}
        >
          <h2 id="save-view-title">Save your triage view</h2>
          <p>
            Keep these filters and sort order for your account in this
            workspace. Saving an existing name updates that view.
          </p>
          <form
            onSubmit={async (e) => {
              e.preventDefault();
              setBusy(true);
              setError("");
              try {
                await api("v1/saved-views", {
                  method: "POST",
                  body: JSON.stringify({ name, filters }),
                });
                await reload();
                setOpen(false);
              } catch (e) {
                setError(
                  e instanceof Error ? e.message : "Could not save view.",
                );
              } finally {
                setBusy(false);
              }
            }}
          >
            <label htmlFor="view-name">View name</label>
            <input
              id="view-name"
              autoFocus
              required
              maxLength={60}
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="High-confidence C2 review"
            />
            {error && (
              <p role="alert" className="form-error">
                {error}
              </p>
            )}
            <div className="modal-actions">
              <Button
                type="button"
                variant="outline"
                disabled={busy}
                onClick={() => setOpen(false)}
              >
                Cancel
              </Button>
              <Button disabled={busy}>
                {busy ? "Saving…" : "Save triage view"}
              </Button>
            </div>
          </form>
        </Modal>
      )}
    </>
  );
}

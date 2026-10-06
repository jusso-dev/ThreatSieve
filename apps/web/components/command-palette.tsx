"use client";
import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { api } from "@/lib/api";
import { usePermission } from "@/lib/access";
import { workspaces } from "@/lib/workspace";
import { detectType } from "../../../packages/intel/src/normalise";
import type { WorkKind } from "../../../packages/schemas/src/enterprise";
import { Modal } from "./ui/modal";
interface Result {
  id: string;
  name: string;
  type: string;
}
export function CommandPalette({ onClose }: { onClose: () => void }) {
  const router = useRouter(),
    canWrite = usePermission("assessment:write");
  const [query, setQuery] = useState(""),
    [results, setResults] = useState<Result[]>([]),
    [active, setActive] = useState(0),
    [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  const input = useRef<HTMLInputElement>(null);
  useEffect(() => {
    input.current?.focus();
  }, []);
  useEffect(() => {
    setActive(0);
    if (query.trim().length < 2) {
      setResults([]);
      return;
    }
    const c = new AbortController();
    const timer = setTimeout(() => {
      void Promise.all([
        api<{ data: Result[] }>("v1/search?q=" + encodeURIComponent(query), {
          signal: c.signal,
        }),
        api<{ data: Result[] }>(
          "v1/workspace/search?q=" + encodeURIComponent(query),
          { signal: c.signal },
        ),
      ])
        .then((pages) => {
          if (!c.signal.aborted)
            setResults(pages.flatMap((p) => p.data).slice(0, 20));
        })
        .catch((e) => {
          if (!c.signal.aborted)
            setError(e instanceof Error ? e.message : "Search unavailable.");
        });
    }, 200);
    return () => {
      clearTimeout(timer);
      c.abort();
    };
  }, [query]);
  let observableType: string | undefined;
  try {
    observableType = detectType(query);
  } catch {
    /* Ambiguous text is a search, not an observable. */
  }
  const go = (path: string) => {
    onClose();
    router.push(path);
  };
  const commands = [
    { name: "New investigation", path: "/cases?new=1", write: true },
    { name: "Assess indicator", path: "/?assess=1", write: true },
    { name: "Bulk analyse", path: "/bulk", write: true },
    { name: "Search actor", path: "/intelligence?type=threat-actor" },
    { name: "Open queue", path: "/" },
    { name: "Create requirement", path: "/requirements?new=1", write: true },
    { name: "Create watchlist", path: "/watchlists?new=1", write: true },
    { name: "Sync source", path: "/sources" },
    { name: "Open investigations", path: "/cases" },
    { name: "Record sighting", path: "/sightings" },
  ].filter(
    (c) =>
      (!c.write || canWrite) &&
      (!query || c.name.toLowerCase().includes(query.toLowerCase())),
  );
  const options = [
    ...results.map((r) => ({
      label: r.name,
      meta: r.type,
      run: () =>
        go(
          (r.type in workspaces
            ? "/" + workspaces[r.type as WorkKind].path
            : "/intelligence") +
            "/" +
            encodeURIComponent(r.id),
        ),
    })),
    ...commands.map((c) => ({
      label: c.name,
      meta: "Command",
      run: () => go(c.path),
    })),
  ];
  return (
    <Modal titleId="command-title" onClose={onClose} busy={busy}>
      <h2 id="command-title">Search & commands</h2>
      <input
        ref={input}
        className="command-input"
        aria-label="Search all intelligence and commands"
        autoComplete="off"
        placeholder="Search intelligence, requirements, investigations…"
        value={query}
        maxLength={200}
        onChange={(e) => {
          setQuery(e.target.value);
          setError("");
        }}
        onKeyDown={(e) => {
          if (e.key === "ArrowDown") {
            e.preventDefault();
            setActive((a) => Math.min(options.length - 1, a + 1));
          }
          if (e.key === "ArrowUp") {
            e.preventDefault();
            setActive((a) => Math.max(0, a - 1));
          }
          if (e.key === "Enter" && options[active]) {
            e.preventDefault();
            options[active]!.run();
          }
        }}
      />
      {observableType && (
        <div className="command-observable">
          <strong>Recognised: {observableType.toUpperCase()}</strong>
          <code>{query}</code>
          <div className="actions">
            <button
              onClick={() => go("/intelligence?q=" + encodeURIComponent(query))}
            >
              Search intelligence
            </button>
            {canWrite && (
              <button
                disabled={busy}
                onClick={async () => {
                  setBusy(true);
                  try {
                    const a = await api<{ assessment_id: string }>(
                      "v1/assess",
                      {
                        method: "POST",
                        body: JSON.stringify({ observable: query }),
                      },
                    );
                    go("/investigations/" + a.assessment_id);
                  } catch (e) {
                    setError(
                      e instanceof Error ? e.message : "Assessment failed.",
                    );
                  } finally {
                    setBusy(false);
                  }
                }}
              >
                Assess observable
              </button>
            )}
            {canWrite && (
              <button
                disabled={busy}
                onClick={async () => {
                  setBusy(true);
                  try {
                    const o = await api<{ id: string }>("v1/observables", {
                      method: "POST",
                      body: JSON.stringify({ observable: query }),
                    });
                    go("/intelligence/" + o.id + "?pin=1");
                  } catch (e) {
                    setError(
                      e instanceof Error
                        ? e.message
                        : "Could not add observable.",
                    );
                  } finally {
                    setBusy(false);
                  }
                }}
              >
                Add to investigation
              </button>
            )}
          </div>
        </div>
      )}
      {error && (
        <p className="form-error" role="alert">
          {error}
        </p>
      )}
      <div
        className="command-results"
        role="listbox"
        aria-label="Search results and commands"
      >
        {options.map((o, i) => (
          <button
            key={o.label + i}
            role="option"
            aria-selected={i === active}
            className={i === active ? "selected" : ""}
            onMouseEnter={() => setActive(i)}
            onClick={o.run}
          >
            <span>{o.label}</span>
            <small>{o.meta}</small>
          </button>
        ))}
      </div>
      <p className="command-hint">
        ↑ ↓ select · Enter open · Esc close. All results respect workspace
        access.
      </p>
    </Modal>
  );
}

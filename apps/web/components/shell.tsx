"use client";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useState, useEffect, useRef } from "react";
import {
  ShieldCheck,
  Radar,
  Network,
  Database,
  Upload,
  Boxes,
  Search,
  Command,
  ArrowUpRight,
  ChevronDown,
  Menu,
  X,
  LogOut,
  Users,
  Crosshair,
  BookOpen,
} from "lucide-react";
import { AccessContext } from "@/lib/access";
import { authClient, authResult } from "@/lib/auth";
import { api, useApi, publicAuthPath } from "@/lib/api";
import { Button } from "./ui/button";
const navigation = [
  { name: "Threat operations", href: "/", icon: Radar },
  { name: "Intelligence library", href: "/intelligence", icon: BookOpen },
  { name: "Threat clusters", href: "/clusters", icon: Network },
  { name: "Intelligence sources", href: "/sources", icon: Database },
  { name: "Bulk analysis", href: "/bulk", icon: Upload },
  { name: "Team & access", href: "/team", icon: Users },
  { name: "Your environment", href: "/inventory", icon: Boxes },
];
export function Shell({ children }: { children: React.ReactNode }) {
  const path = usePathname();
  if (publicAuthPath(path)) return children;
  return <WorkspaceShell>{children}</WorkspaceShell>;
}
function WorkspaceShell({ children }: { children: React.ReactNode }) {
  const path = usePathname();
  const router = useRouter();
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<
    { id: string; name: string; type: string }[]
  >([]);
  const [searchError, setSearchError] = useState("");
  const [searching, setSearching] = useState(false);
  const [activeResult, setActiveResult] = useState(-1);
  const [open, setOpen] = useState(false);
  const input = useRef<HTMLInputElement>(null);
  const pendingSearch = useRef<string | null>(null);
  const sidebar = useRef<HTMLElement>(null);
  const [assessing, setAssessing] = useState(false);
  const me = useApi<{
    tenantId: string;
    scopes: string[];
    workspaceName?: string;
    userName?: string;
    role?: string;
  }>("v1/me");
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        input.current?.focus();
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, []);
  useEffect(() => {
    if (query.length < 2) {
      setResults([]);
      setSearching(false);
      return;
    }
    const controller = new AbortController();
    setSearchError("");
    setResults([]);
    setActiveResult(-1);
    setSearching(true);
    const timer = setTimeout(() => {
      void api<{ data: { id: string; name: string; type: string }[] }>(
        "v1/search?q=" + encodeURIComponent(query),
        { signal: controller.signal },
      )
        .then((r) => {
          if (!controller.signal.aborted) {
            setResults(r.data);
            if (pendingSearch.current === query) {
              pendingSearch.current = null;
              if (r.data[0]) {
                setQuery("");
                router.push(
                  "/intelligence/" + encodeURIComponent(r.data[0].id),
                );
              } else void investigate(query);
            }
          }
        })
        .catch((e) => {
          if (!controller.signal.aborted)
            setSearchError(
              e instanceof Error
                ? e.message
                : "We couldn’t search intelligence. Please try again.",
            );
        })
        .finally(() => {
          if (!controller.signal.aborted) setSearching(false);
        });
    }, 250);
    return () => {
      clearTimeout(timer);
      controller.abort();
    };
  }, [query]);
  useEffect(() => {
    const media = window.matchMedia("(max-width:680px)");
    const changed = () => {
      if (!media.matches) setOpen(false);
    };
    media.addEventListener("change", changed);
    return () => media.removeEventListener("change", changed);
  }, []);
  useEffect(() => {
    if (!open) return;
    const previous = document.activeElement as HTMLElement | null;
    const overflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    const nodes = () =>
      Array.from(
        sidebar.current!.querySelectorAll<HTMLElement>(
          'a[href],button:not([disabled]),input:not([disabled]),[tabindex="0"]',
        ),
      ).filter((el) => el.getClientRects().length > 0);
    nodes()[0]?.focus();
    const key = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        setOpen(false);
      }
      if (event.key === "Tab") {
        const targets = nodes();
        const first = targets[0],
          last = targets.at(-1);
        if (event.shiftKey && document.activeElement === first) {
          event.preventDefault();
          last?.focus();
        } else if (!event.shiftKey && document.activeElement === last) {
          event.preventDefault();
          first?.focus();
        }
      }
    };
    document.addEventListener("keydown", key);
    return () => {
      document.removeEventListener("keydown", key);
      document.body.style.overflow = overflow;
      previous?.focus();
    };
  }, [open]);
  const investigate = async (value: string) => {
    if (
      assessing ||
      !me.data?.scopes.some((s) => s === "admin" || s === "assessment:write")
    )
      return;
    setAssessing(true);
    setSearchError("");
    try {
      const a = await api<{ assessment_id: string }>("v1/assess", {
        method: "POST",
        body: JSON.stringify({ observable: value }),
      });
      setQuery("");
      router.push("/investigations/" + a.assessment_id);
    } catch (e) {
      setSearchError(e instanceof Error ? e.message : "Assessment failed");
    } finally {
      setAssessing(false);
    }
  };
  return (
    <div className="app-shell">
      {open && (
        <button
          className="nav-backdrop"
          aria-label="Close navigation overlay"
          onClick={() => setOpen(false)}
        />
      )}
      <aside
        ref={sidebar}
        aria-label="Workspace navigation"
        role={open ? "dialog" : undefined}
        aria-modal={open ? true : undefined}
        className={"sidebar " + (open ? "sidebar-open" : "")}
      >
        <button
          className="sidebar-close"
          aria-label="Close navigation"
          onClick={() => setOpen(false)}
        >
          <X size={18} />
        </button>
        <Link className="brand" href="/">
          <span className="brand-symbol">
            <ShieldCheck size={23} />
          </span>
          ThreatSieve<span className="brand-period">.</span>
        </Link>
        <button className="workspace" onClick={() => router.push("/team")}>
          <span className="workspace-avatar">TS</span>
          <span>
            {me.data?.workspaceName ?? "Your workspace"}
            <small>
              {me.data?.tenantId === "demo-tenant"
                ? "Demonstration environment"
                : "Intelligence operations"}
            </small>
          </span>
          <ChevronDown size={14} />
        </button>
        <div className="nav-label">WORKSPACE</div>
        <nav>
          {navigation.map((item) => (
            <Link
              key={item.href}
              href={item.href}
              onClick={() => setOpen(false)}
              aria-current={
                path === item.href ||
                (item.href === "/intelligence" &&
                  path.startsWith("/intelligence/"))
                  ? "page"
                  : undefined
              }
              className={
                "nav-link " +
                (path === item.href ||
                (item.href === "/" && path.startsWith("/investigations")) ||
                (item.href === "/intelligence" &&
                  path.startsWith("/intelligence/"))
                  ? "active"
                  : "")
              }
            >
              <item.icon size={18} />
              {item.name}
              {item.href === "/" && <span className="nav-indicator" />}
            </Link>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="principle">
            <Crosshair size={18} />
            <strong>Evidence before certainty.</strong>
            <p>
              Every decision has a source.
              <br />
              Every unknown stays visible.
            </p>
          </div>
          <button
            className="profile"
            onClick={() => {
              void authResult(
                authClient.signOut(),
                "You’ve signed out securely.",
              )
                .then(() => router.push("/sign-in"))
                .catch(() => {});
            }}
          >
            <span className="profile-avatar">TA</span>
            <span>
              {me.data?.userName ?? "Your account"}
              <small>{me.data?.role ?? "Workspace session"} · Sign out</small>
            </span>
            <LogOut size={15} />
          </button>
        </div>
      </aside>
      <a href="#main-content" className="skip-link">
        Skip to main content
      </a>
      <div className="main-shell" inert={open}>
        <header className="topbar">
          <button
            aria-label="Toggle navigation"
            className="mobile-menu"
            onClick={() => setOpen(!open)}
          >
            {open ? <X size={20} /> : <Menu size={20} />}
          </button>
          <div className="breadcrumb">
            Workspace <span>/</span>{" "}
            <strong>
              {path.startsWith("/investigations")
                ? "Investigation"
                : path.startsWith("/intelligence")
                  ? "Intelligence library"
                  : (navigation.find((n) => n.href === path)?.name ??
                    "Threat operations")}
            </strong>
          </div>
          <div className="global-search">
            <Search size={16} />
            <input
              ref={input}
              aria-label="Search intelligence"
              disabled={me.loading}
              aria-busy={me.loading}
              placeholder="Search IP, domain, hash, CVE…"
              value={query}
              aria-controls={
                query.length >= 2 ? "global-search-results" : undefined
              }
              onChange={(e) => {
                pendingSearch.current = null;
                setQuery(e.target.value);
                setSearching(e.target.value.length >= 2);
              }}
              onKeyDown={(e) => {
                if (e.key === "ArrowDown" || e.key === "ArrowUp") {
                  e.preventDefault();
                  setActiveResult((i) =>
                    e.key === "ArrowDown"
                      ? Math.min(results.length - 1, i + 1)
                      : Math.max(0, i - 1),
                  );
                }
                if (e.key === "Enter" && query && searching)
                  pendingSearch.current = query;
                if (e.key === "Enter" && query && !searching) {
                  const result = results[activeResult >= 0 ? activeResult : 0];
                  if (result) {
                    setQuery("");
                    router.push(
                      "/intelligence/" + encodeURIComponent(result.id),
                    );
                  } else void investigate(query);
                }
                if (e.key === "Escape") {
                  pendingSearch.current = null;
                  setQuery("");
                }
              }}
            />
            <kbd>
              <Command size={11} /> K
            </kbd>
            {query.length >= 2 && (
              <div className="search-results" id="global-search-results">
                <span className="sr-only" role="status">
                  {activeResult >= 0 ? results[activeResult]?.name : ""}
                </span>
                {searching && <p role="status">Searching intelligence…</p>}
                {!searching && !results.length && !searchError && (
                  <p role="status">
                    No matching intelligence. You can assess a new observable
                    below.
                  </p>
                )}
                {results.map((r, index) => (
                  <button
                    key={r.id}
                    className={index === activeResult ? "search-active" : ""}
                    onClick={() => {
                      setQuery("");
                      router.push("/intelligence/" + encodeURIComponent(r.id));
                    }}
                  >
                    <span>{r.name}</span>
                    <small>{r.type}</small>
                    <ArrowUpRight size={14} />
                  </button>
                ))}
                <button
                  disabled={
                    assessing ||
                    !me.data?.scopes.some(
                      (s) => s === "admin" || s === "assessment:write",
                    )
                  }
                  onClick={() => void investigate(query)}
                >
                  <Search size={14} />
                  {assessing ? "Assessing…" : <>Assess “{query}”</>}
                </button>
                {searchError && <p role="alert">{searchError}</p>}
              </div>
            )}
          </div>
          {searchError && query.length < 2 && (
            <p role="alert" className="text-red">
              {searchError}
            </p>
          )}
          <span className="top-status">
            <span className={me.error ? "status-dot warning" : "status-dot"} />
            {me.error
              ? "Connection issue"
              : me.loading
                ? "Connecting…"
                : "Workspace connected"}
          </span>
        </header>
        <main id="main-content">
          <AccessContext value={me.data?.scopes ?? []}>
            {children}
          </AccessContext>
        </main>
        <footer className="app-footer">
          <span>
            <ShieldCheck size={13} /> ThreatSieve decision layer
          </span>
          <span>Probabilities are estimates. Evidence is traceable.</span>
        </footer>
      </div>
    </div>
  );
}
export function PageHeader({
  eyebrow,
  title,
  description,
  action,
}: {
  eyebrow?: string;
  title: string;
  description: string;
  action?: React.ReactNode;
}) {
  return (
    <div className="page-heading">
      <div>
        {eyebrow && <div className="eyebrow">{eyebrow}</div>}
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      {action}
    </div>
  );
}
export function DataState({
  loading,
  error,
  empty,
}: {
  loading?: boolean;
  error?: string;
  empty?: boolean;
}) {
  if (error)
    return (
      <div className="state-panel error" role="alert">
        <strong>Unable to load intelligence</strong>
        <p>{error}</p>
        <Button variant="outline" onClick={() => window.location.reload()}>
          Try again
        </Button>
      </div>
    );
  if (loading)
    return (
      <div className="state-panel" role="status">
        <span className="loader" />
        <p>Loading evidence-backed intelligence…</p>
      </div>
    );
  if (empty)
    return (
      <div className="state-panel">
        <ShieldCheck size={32} />
        <h3>No intelligence in this view</h3>
        <p>Sync your sources or submit an observable to begin.</p>
        <Link href="/sources" className="text-link">
          Manage intelligence sources <ArrowUpRight size={14} />
        </Link>
      </div>
    );
  return null;
}

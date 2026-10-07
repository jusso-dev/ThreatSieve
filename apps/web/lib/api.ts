"use client";
import { toast } from "sonner";
import { useEffect, useState, useCallback, useRef } from "react";
const mutationMessage = (path: string) => {
  if (/\/notifications\/[^/]+\/read$/.test(path))
    return "Notification marked as read.";
  if (/\/tags$/.test(path)) return "Workspace tags updated.";
  if (/\/notes$/.test(path))
    return "Analyst entry saved to the decision history.";
  if (/\/packages$/.test(path))
    return "Export queued. Progress will appear here.";
  if (/\/publish$/.test(path)) return "Collection snapshot published to TAXII.";
  if (path === "v1/sightings") return "Sighting recorded in your workspace.";
  if (path.includes("/saved-views")) return "Saved views updated.";
  if (path.includes("/sync"))
    return "Source sync started. Progress will appear in the source list.";
  if (path.includes("/reclassify"))
    return "Reclassification queued. Your updated decision will appear shortly.";
  if (/\/(confirm|reject|modify)$/.test(path))
    return "Analyst decision saved and recorded in the audit log.";
  if (path.includes("/environment"))
    return "Environment saved. New assessments will use your updated context.";
  if (path.includes("/uploads") || path.includes("/bulk"))
    return "Import started. You can follow its progress here.";
  if (path.includes("/assess")) return "Assessment ready to investigate.";
  if (path.includes("/session")) return "You’ve signed out securely.";
  return "Changes saved.";
};
class WorkspaceRequired extends Error {}
export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  try {
    const result = await request<T>(path, init);
    if (init?.method && !["GET", "HEAD"].includes(init.method.toUpperCase()))
      toast.success(mutationMessage(path));
    return result;
  } catch (error) {
    if (init?.signal?.aborted) throw error;
    const message =
      error instanceof TypeError
        ? "Check your connection and try again."
        : error instanceof Error
          ? error.message
          : "We couldn’t complete your request. Please try again.";
    if (!(error instanceof WorkspaceRequired))
      toast.error(message, { id: "request-error:" + path.split("?")[0] });
    throw new Error(message);
  }
}
async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers);
  if (init?.body && !headers.has("Content-Type"))
    headers.set("Content-Type", "application/json");
  const response = await fetch("/api/" + path.replace(/^\//, ""), {
    credentials: "same-origin",
    ...init,
    headers,
  });
  if (response.status === 401) {
    if (
      typeof window !== "undefined" &&
      !publicAuthPath(window.location.pathname)
    )
      window.location.assign("/sign-in");
    throw new Error("Sign in to your workspace");
  }
  let body: unknown;
  try {
    body = await response.json();
  } catch {
    throw new Error(
      response.ok
        ? "We couldn’t read the response. Please refresh and try again."
        : "We couldn’t complete your request. Please try again shortly.",
    );
  }
  if (!response.ok) {
    const error = body as { error?: { message?: string; code?: string } };
    if (
      error.error?.code === "WORKSPACE_REQUIRED" &&
      window.location.pathname !== "/team"
    )
      window.location.assign("/team");
    if (error.error?.code === "WORKSPACE_REQUIRED")
      throw new WorkspaceRequired(
        "Choose a workspace or accept a team invitation.",
      );
    const friendly: Record<number, string> = {
      403: "Your account doesn’t have permission for this action. Ask a team admin for help.",
      404: "This item is no longer available. Refresh the page and try again.",
      429: "You’re making requests too quickly. Wait a minute and try again.",
      500: "We couldn’t complete your request. Please try again shortly.",
      502: "An intelligence provider is unavailable. Please try again shortly.",
      503: "ThreatSieve is temporarily unavailable. Please try again shortly.",
    };
    throw new Error(
      friendly[response.status] ??
        error.error?.message ??
        "Check your input and try again.",
    );
  }
  return body as T;
}
export function useApi<T>(path: string) {
  const [state, setState] = useState<{
    path: string;
    data?: T;
    error?: string;
    loading: boolean;
  }>({ path, loading: true });
  const controller = useRef<AbortController | null>(null);
  const reload = useCallback(async () => {
    controller.current?.abort();
    const request = new AbortController();
    controller.current = request;
    setState((previous) => ({
      path,
      data: previous.path === path ? previous.data : undefined,
      loading: true,
    }));
    try {
      const data = await api<T>(path, { signal: request.signal });
      if (!request.signal.aborted) setState({ path, data, loading: false });
    } catch (error) {
      if (!request.signal.aborted)
        setState({
          path,
          error: error instanceof Error ? error.message : "Request failed",
          loading: false,
        });
    }
  }, [path]);
  useEffect(() => {
    void reload();
    return () => controller.current?.abort();
  }, [reload]);
  return {
    ...(state.path === path
      ? state
      : { loading: true, data: undefined, error: undefined }),
    reload,
  };
}

export const publicAuthPath = (path: string) =>
  [
    "/sign-in",
    "/sign-up",
    "/forgot-password",
    "/reset-password",
    "/accept-invitation",
  ].includes(path);

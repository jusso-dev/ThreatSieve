"use client";
import { useEffect, useState, useCallback, useRef } from "react";
export async function api<T>(path: string, init?: RequestInit): Promise<T> {
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
      window.location.pathname !== "/sign-in"
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
        ? "The API returned an invalid response"
        : "Request failed (" + response.status + "). Please retry.",
    );
  }
  if (!response.ok) {
    const error = body as { error?: { message?: string } };
    throw new Error(error.error?.message ?? "Request failed");
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

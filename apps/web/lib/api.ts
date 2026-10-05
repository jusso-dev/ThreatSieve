"use client";
import { useEffect, useState, useCallback } from "react";
export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch("/api/" + path.replace(/^\//, ""), {
    credentials: "same-origin",
    ...init,
    headers: {
      ...(init?.body ? { "Content-Type": "application/json" } : {}),
      ...init?.headers,
    },
  });
  if (response.status === 401) {
    if (
      typeof window !== "undefined" &&
      window.location.pathname !== "/sign-in"
    )
      window.location.assign("/sign-in");
    throw new Error("Sign in to your workspace");
  }
  const body: unknown = await response.json();
  if (!response.ok) {
    const error = body as { error?: { message?: string } };
    throw new Error(error.error?.message ?? "Request failed");
  }
  return body as T;
}
export function useApi<T>(path: string) {
  const [data, setData] = useState<T>();
  const [error, setError] = useState<string>();
  const [loading, setLoading] = useState(true);
  const reload = useCallback(() => {
    setLoading(true);
    return api<T>(path)
      .then((d) => {
        setData(d);
        setError(undefined);
      })
      .catch((e) => setError(e instanceof Error ? e.message : "Request failed"))
      .finally(() => setLoading(false));
  }, [path]);
  useEffect(() => {
    void reload();
  }, [reload]);
  return { data, error, loading, reload };
}

"use client";
import { createContext, useContext } from "react";
export const AccessContext = createContext<string[]>([]);
export function usePermission(scope: string) {
  const scopes = useContext(AccessContext);
  return scopes.includes("admin") || scopes.includes(scope);
}

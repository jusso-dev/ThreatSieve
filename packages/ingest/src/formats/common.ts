import type { z } from "zod";
import type { ItemIssue, NativeItem } from "../schema";

/** One native-shaped item produced by a format mapper, or why it failed. */
export interface Mapped {
  /** Identifier in the source document, such as a STIX id or CSAF tracking id. */
  source_ref?: string;
  item?: Partial<Record<keyof NativeItem, unknown>>;
  issues?: ItemIssue[];
  warnings: string[];
}
export const isRecord = (v: unknown): v is Record<string, unknown> =>
  !!v && typeof v === "object" && !Array.isArray(v);
export const str = (v: unknown) =>
  typeof v === "string" && v.trim() ? v : undefined;
export const records = (v: unknown) =>
  Array.isArray(v) ? v.filter(isRecord) : [];

/** Mappers trim oversize text rather than rejecting a real advisory for it. */
export function clip(
  value: string | undefined,
  max: number,
  field: string,
  warnings: string[],
) {
  if (value === undefined || value.length <= max) return value;
  warnings.push(field + " truncated to " + max + " characters");
  return value.slice(0, max);
}
/** Keeps only http(s) links; anything else is dropped with a warning. */
export function httpLinks(
  refs: { url: unknown; title?: unknown }[],
  warnings: string[],
) {
  const out: { url: string; title?: string }[] = [];
  let dropped = 0;
  for (const ref of refs) {
    const url = str(ref.url);
    if (!url || !/^https?:\/\/[^\s]+$/i.test(url) || url.length > 2048) {
      dropped++;
      continue;
    }
    if (out.some((r) => r.url === url)) continue;
    const title = str(ref.title)?.slice(0, 500);
    out.push(title ? { url, title } : { url });
  }
  if (dropped) warnings.push(dropped + " non-HTTP(S) reference(s) dropped");
  if (out.length > 200) warnings.push("References truncated to 200");
  return out.slice(0, 200);
}
export function documentIssues(error: z.ZodError): ItemIssue[] {
  return error.issues.slice(0, 50).map((i) => ({
    path: i.path.map((p) => (typeof p === "symbol" ? String(p) : p)),
    message: i.message,
  }));
}

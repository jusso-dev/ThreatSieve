import { ZodError } from "zod";
/**
 * Fixed, non-sensitive reason for a failed production probe request. Never
 * echoes the error message, URL or response body, so public CI logs stay free
 * of tenant data while still separating timeouts from HTTP and shape failures.
 */
export function probeFailureReason(error: unknown): string {
  if (error instanceof Error && error.name === "TimeoutError")
    return "timed out after 30 seconds";
  if (error instanceof Error && /^ProbeHTTP\d{3}$/.test(error.message))
    return "HTTP " + error.message.slice(9);
  if (error instanceof ZodError || error instanceof SyntaxError)
    return "unexpected response shape";
  return "request failed";
}
/**
 * Subjects that are pipeline stages, platform components or shared public
 * feeds. Anything else (tenant connectors, private sources) is never printed.
 */
const PUBLIC_SUBJECTS = new Set([
  "scheduler",
  "archive",
  "outbox",
  "classifier",
  "feed-sync",
  "bulk",
  "ingest",
  "operations",
  "normalise",
  "enrich",
  "correlate",
  "classify",
  "export",
  "mitre",
  "misp",
  "threatfox",
  "urlhaus",
  "feodo",
  "cisa-kev",
]);
/** Deduplicated `CODE(subject)` labels, with subjects only from the allowlist. */
export function alertLabels(
  alerts: { code: string; severity: string; subject?: string }[],
  severity: "critical" | "warning",
): string[] {
  return [
    ...new Set(
      alerts
        .filter((a) => a.severity === severity)
        .map((a) =>
          a.subject && PUBLIC_SUBJECTS.has(a.subject)
            ? a.code + "(" + a.subject + ")"
            : a.code,
        ),
    ),
  ];
}

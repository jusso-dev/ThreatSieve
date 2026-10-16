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

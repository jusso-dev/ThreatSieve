export function log(event: {
  request_id?: string;
  correlation_id?: string;
  tenant_id?: string;
  job_id?: string;
  stage?: string;
  duration_ms?: number;
  result: string;
  error_type?: string;
}) {
  console.log(
    JSON.stringify({ ...event, timestamp: new Date().toISOString() }),
  );
}
export class AppError extends Error {
  constructor(
    public code: string,
    public status:
      400 | 401 | 403 | 404 | 406 | 409 | 413 | 422 | 429 | 500 | 502 | 503,
    message: string,
  ) {
    super(message);
  }
}
export function errorType(error: unknown) {
  if (!(error instanceof Error)) return "UnknownError";
  if (error instanceof AppError) return error.code;
  // Store only stable categories, never provider messages containing URLs or credentials.
  if (/D1|SQLITE/i.test(error.message)) {
    if (/overload|too many|busy|rate.?limit/i.test(error.message))
      return "D1Overloaded";
    if (/timeout|timed out/i.test(error.message)) return "D1Timeout";
    if (/constraint|foreign key/i.test(error.message)) return "D1Constraint";
    return "D1Error";
  }
  if (/subrequest.*limit|too many subrequests/i.test(error.message))
    return "SubrequestLimit";
  if (error.name === "TimeoutError" || /timeout|timed out/i.test(error.message))
    return "UpstreamTimeout";
  if (error.name === "AbortError") return "UpstreamAborted";
  if (/credential required/i.test(error.message))
    return "FeedCredentialsMissing";
  if (/upstream HTTP (401|403)\b/i.test(error.message))
    return "UpstreamAccessDenied";
  if (/upstream HTTP 429\b/i.test(error.message)) return "UpstreamRateLimited";
  if (/upstream HTTP 5\d\d\b/i.test(error.message))
    return "UpstreamUnavailable";
  if (/network|fetch failed|ECONNRESET|ENOTFOUND/i.test(error.message))
    return "UpstreamNetwork";
  return error.constructor.name;
}

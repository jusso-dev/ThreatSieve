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
      400 | 401 | 403 | 404 | 409 | 413 | 422 | 429 | 500 | 502 | 503,
    message: string,
  ) {
    super(message);
  }
}
export function errorType(error: unknown) {
  return error instanceof Error ? error.constructor.name : "UnknownError";
}

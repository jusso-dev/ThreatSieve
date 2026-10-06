export interface OperationalAlert {
  code: string;
  severity: "warning" | "critical";
  subject: string;
  message: string;
}
export interface OperationalReport {
  schema_version: "1.0";
  checked_at: string;
  status: "healthy" | "degraded" | "critical";
  heartbeat: string | null;
  archive_heartbeat: string | null;
  feeds: {
    id: string;
    name: string;
    status: string;
    configured: boolean;
    enabled: number;
    last_sync: string | null;
    next_sync: string | null;
    records_processed: number;
    records_added: number;
    records_updated: number;
    errors: number;
  }[];
  jobs: {
    stage: string;
    status: string;
    count: number;
    oldest: string;
    stale_result_count: number;
  }[];
  outbox: { pending: number; oldest: string | null };
  usage: { calls: number; input_tokens: number; daily_limit: number };
  integrations: {
    connector_id: string;
    last_poll_at: string;
    last_success_at: string | null;
    status: string;
    error_type: string | null;
    version: string;
  }[];
  alerts: OperationalAlert[];
}

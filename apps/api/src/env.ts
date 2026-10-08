import type { FeedSecrets } from "../../../packages/intel/src/feeds";
// Wrangler generates every binding. Widen configurable string literals without duplicating bindings.
export type AppEnv = {
  [K in keyof Env]: Env[K] extends string ? string : Env[K];
} & FeedSecrets & {
    BETTER_AUTH_SECRET?: string;
    INTEGRATION_TARGETS?: string;
    INTEGRATION_SECRETS?: string;
    // Optional Workers VPC service for a private TAXII server; see docs/opencti.md.
    OPENCTI_VPC?: Fetcher;
  };

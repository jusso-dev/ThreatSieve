import type { FeedSecrets } from "../../../packages/intel/src/feeds";
// Wrangler generates every binding. Widen configurable string literals without duplicating bindings.
export type AppEnv = {
  [K in keyof Env]: Env[K] extends string ? string : Env[K];
} & FeedSecrets;

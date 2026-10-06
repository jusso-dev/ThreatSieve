import type { AppEnv } from "./env";
import type { Principal } from "../../../packages/schemas/src/index";
export type ApiContext = {
  Bindings: AppEnv;
  Variables: { principal: Principal; requestId: string };
};

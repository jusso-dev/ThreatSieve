import { mkdirSync, writeFileSync } from "node:fs";
import { ingestOpenApi } from "../packages/ingest/src/openapi";

// Writes the committed copy of the spec served at GET /openapi/ingest.json.
mkdirSync("docs/openapi", { recursive: true });
writeFileSync(
  "docs/openapi/ingest.json",
  JSON.stringify(ingestOpenApi(), null, 2) + "\n",
);
console.log("Wrote docs/openapi/ingest.json");

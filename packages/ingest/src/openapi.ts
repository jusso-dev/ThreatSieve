import { z } from "zod";
import { MEDIA_TYPES } from "./formats/index";
import {
  INGEST_MAX_BODY_BYTES,
  INGEST_MAX_ITEMS,
  IngestEnvelope,
  NativeItem,
} from "./schema";

/** JSON Schema (2020-12) generated from the zod schema that validates requests. */
export function nativeItemJsonSchema() {
  return z.toJSONSchema(NativeItem, { target: "draft-2020-12", io: "input" });
}
function component(schema: z.ZodType) {
  const { $schema: _, ...rest } = z.toJSONSchema(schema, {
    target: "draft-2020-12",
    io: "input",
  }) as Record<string, unknown>;
  return rest;
}

const ref = (name: string) => ({ $ref: "#/components/schemas/" + name });
const error = (description: string) => ({
  description,
  content: { "application/json": { schema: ref("Error") } },
});
const Issue = {
  type: "object",
  required: ["path", "message"],
  properties: {
    path: { type: "array", items: { type: ["string", "integer"] } },
    message: { type: "string" },
  },
};
const ItemError = {
  type: "object",
  required: ["index", "document", "issues"],
  properties: {
    index: {
      type: "integer",
      description: "Position among the items produced from the request.",
    },
    document: {
      type: "integer",
      description: "Position of the source document in the request.",
    },
    source_ref: {
      type: "string",
      description: "STIX id, CSAF tracking id or OSV id.",
    },
    external_id: { type: "string" },
    issues: { type: "array", items: Issue },
  },
};
const severity = {
  type: "string",
  enum: ["info", "low", "medium", "high", "critical"],
};
const NormalisedItem = {
  type: "object",
  description: "An item after mapping and normalisation.",
  properties: {
    type: { type: "string", enum: ["alert", "advisory"] },
    format: { type: "string", enum: ["native", "stix", "csaf", "osv"] },
    external_id: { type: "string" },
    external_id_source: { type: "string", enum: ["provided", "derived"] },
    title: {
      type: "string",
      description: "Plain text; markup and invisible characters removed.",
    },
    summary: { type: ["string", "null"] },
    severity,
    severity_source: {
      type: "string",
      enum: ["provided", "vendor", "cvss", "default"],
    },
    vendor_severity: {
      type: ["string", "number", "null"],
      description: "The producer's value, unchanged.",
    },
    source: {
      type: "object",
      properties: {
        name: { type: "string" },
        url: { type: ["string", "null"] },
        vendor: { type: ["string", "null"] },
      },
    },
    published_at: { type: ["string", "null"], format: "date-time" },
    updated_at: { type: ["string", "null"], format: "date-time" },
    cve_ids: { type: "array", items: { type: "string" } },
    cvss: {
      type: ["object", "null"],
      properties: {
        version: { type: "string" },
        score: { type: ["number", "null"] },
        vector: { type: ["string", "null"] },
      },
    },
    affected_products: { type: "array", items: { type: "object" } },
    indicators: {
      type: "array",
      items: {
        type: "object",
        properties: {
          type: { type: "string" },
          value: { type: "string" },
          display_value: {
            type: "string",
            description: "Defanged, for display only.",
          },
          confidence: { type: "integer" },
        },
      },
    },
    attack_techniques: { type: "array", items: { type: "string" } },
    references: { type: "array", items: { type: "object" } },
    tags: { type: "array", items: { type: "string" } },
    tlp: {
      type: "string",
      enum: ["clear", "green", "amber", "amber+strict", "red"],
    },
    tlp_source: { type: "string", enum: ["provided", "default"] },
  },
};
const Normalisation = {
  type: "object",
  properties: {
    changes: {
      type: "array",
      items: {
        type: "object",
        properties: { path: Issue.properties.path, from: {}, to: {} },
      },
    },
    warnings: { type: "array", items: { type: "string" } },
  },
};

/** OpenAPI 3.1 description of the ingest endpoints, served at /openapi/ingest.json. */
export function ingestOpenApi() {
  const documents = {
    stix: {
      type: "object",
      description: "A STIX 2.1 bundle.",
      required: ["type", "id", "objects"],
    },
    csaf: {
      description: "A CSAF 2.0 document, or an array of them.",
      oneOf: [
        { type: "object" },
        {
          type: "array",
          minItems: 1,
          maxItems: INGEST_MAX_ITEMS,
          items: { type: "object" },
        },
      ],
    },
    osv: {
      description: "An OSV record, or an array of them.",
      oneOf: [
        { type: "object" },
        {
          type: "array",
          minItems: 1,
          maxItems: INGEST_MAX_ITEMS,
          items: { type: "object" },
        },
      ],
    },
  };
  const content: Record<string, { schema: unknown }> = {};
  for (const [media, format] of Object.entries(MEDIA_TYPES))
    content[media] = {
      schema:
        format === "native"
          ? {
              oneOf: [
                ref("NativeItem"),
                {
                  type: "array",
                  minItems: 1,
                  maxItems: INGEST_MAX_ITEMS,
                  items: ref("NativeItem"),
                },
                ref("IngestEnvelope"),
              ],
            }
          : documents[format],
    };
  return {
    openapi: "3.1.0",
    info: {
      title: "ThreatSieve ingest API",
      version: "1.0.0",
      description:
        "Accepts structured security alerts and advisories as native JSON, STIX 2.1, CSAF 2.0 or OSV, maps them to one schema and stores them per tenant. " +
        "Bodies are limited to " +
        INGEST_MAX_BODY_BYTES / 1048576 +
        " MiB and " +
        INGEST_MAX_ITEMS +
        " items. " +
        "Through the web app the same routes are served under /api.",
    },
    servers: [
      { url: "/", description: "API Worker" },
      { url: "/api", description: "Web proxy" },
    ],
    security: [{ bearer: [] }],
    paths: {
      "/v1/ingest": {
        post: {
          operationId: "ingest",
          summary: "Submit one alert or advisory, or a batch",
          description:
            "The format comes from Content-Type, or from the `format` field of an `application/json` envelope. " +
            "A single document is stored synchronously (201 created, 200 when it matched an existing item). " +
            "Arrays, envelopes and STIX bundles are batches: valid items are queued (202) and invalid ones are reported per item. " +
            "Requires scope `ingest:write`.",
          parameters: [
            {
              name: "Idempotency-Key",
              in: "header",
              required: false,
              schema: { type: "string", minLength: 1, maxLength: 200 },
              description:
                "Repeat the key with the same body to receive the first response again; a different body returns 409.",
            },
          ],
          requestBody: { required: true, content },
          responses: {
            "200": {
              description:
                "The item matched an existing one (same source and external ID) and was updated or left unchanged.",
              content: { "application/json": { schema: ref("StoredResult") } },
            },
            "201": {
              description: "The item was created.",
              content: { "application/json": { schema: ref("StoredResult") } },
            },
            "202": {
              description: "Batch accepted for asynchronous storage.",
              content: { "application/json": { schema: ref("BatchAccepted") } },
            },
            "400": {
              description:
                "Invalid body, or no item passed validation (`error.items` lists issues per item).",
              content: { "application/json": { schema: ref("Error") } },
            },
            "401": error("Missing or invalid credentials."),
            "403": error("Missing scope `ingest:write`."),
            "409": error("Idempotency key reused with a different body."),
            "413": error("Body or item count over the limit."),
            "415": error("Unsupported Content-Type."),
            "429": error("Rate limit exceeded; see Retry-After."),
          },
        },
      },
      "/v1/ingest/{id}": {
        get: {
          operationId: "getIngested",
          summary: "Fetch a stored item (ing_…) or a batch's status (inb_…)",
          description:
            "Requires scope `ingest:read`. Only the submitting tenant can read an item.",
          parameters: [
            {
              name: "id",
              in: "path",
              required: true,
              schema: {
                type: "string",
                pattern: "^(ing|inb)_[a-f0-9]{32,40}$",
              },
            },
          ],
          responses: {
            "200": {
              description:
                "The item with its normalisation record and raw payload, or the batch status.",
              content: {
                "application/json": {
                  schema: { oneOf: [ref("StoredItem"), ref("BatchStatus")] },
                },
              },
            },
            "404": error("Not found in this tenant."),
          },
        },
      },
      "/v1/ingest/metrics": {
        get: {
          operationId: "ingestMetrics",
          summary: "Daily item counters for this tenant",
          parameters: [
            {
              name: "days",
              in: "query",
              schema: { type: "integer", minimum: 1, maximum: 90, default: 7 },
            },
          ],
          responses: {
            "200": {
              description: "Counters per UTC day.",
              content: { "application/json": { schema: { type: "object" } } },
            },
          },
        },
      },
    },
    components: {
      securitySchemes: {
        bearer: {
          type: "http",
          scheme: "bearer",
          description: "A ThreatSieve API key.",
        },
      },
      schemas: {
        NativeItem: component(NativeItem),
        IngestEnvelope: component(IngestEnvelope),
        NormalisedItem,
        Normalisation,
        ItemError,
        StoredResult: {
          type: "object",
          properties: {
            id: { type: "string" },
            status: {
              type: "string",
              enum: ["created", "updated", "unchanged"],
            },
            revision: { type: "integer" },
            item: ref("NormalisedItem"),
            normalisation: ref("Normalisation"),
          },
        },
        StoredItem: {
          type: "object",
          properties: {
            id: { type: "string" },
            kind: { const: "item" },
            revision: { type: "integer" },
            received_at: { type: "string", format: "date-time" },
            stored_at: { type: "string", format: "date-time" },
            last_ingest_id: { type: "string" },
            item: ref("NormalisedItem"),
            normalisation: ref("Normalisation"),
            raw: { description: "The original payload as received." },
          },
        },
        BatchAccepted: {
          type: "object",
          properties: {
            ingest_id: { type: "string" },
            status: { const: "queued" },
            status_url: { type: "string" },
            format: { type: "string" },
            received: { type: "integer" },
            accepted: { type: "integer" },
            rejected: { type: "integer" },
            deduplicated: {
              type: "integer",
              description: "Items repeated within this request.",
            },
            items: { type: "array", items: { type: "object" } },
            errors: { type: "array", items: ref("ItemError") },
          },
        },
        BatchStatus: {
          type: "object",
          properties: {
            id: { type: "string" },
            kind: { const: "batch" },
            status: { type: "string", enum: ["queued", "complete", "failed"] },
            received: { type: "integer" },
            accepted: { type: "integer" },
            rejected: { type: "integer" },
            deduplicated: { type: "integer" },
            created: { type: "integer" },
            updated: { type: "integer" },
            unchanged: { type: "integer" },
            items: { type: "array", items: { type: "object" } },
            errors: { type: "array", items: ref("ItemError") },
          },
        },
        Error: {
          type: "object",
          properties: {
            error: {
              type: "object",
              required: ["code", "message"],
              properties: {
                code: { type: "string" },
                message: { type: "string" },
                request_id: { type: "string" },
                issues: { type: "array", items: Issue },
                items: { type: "array", items: ref("ItemError") },
              },
            },
          },
        },
      },
    },
  };
}

import { AppError } from "../../../observability/src/index";
import {
  INGEST_MAX_ITEMS,
  IngestEnvelope,
  type IngestFormat,
  type TlpInput,
} from "../schema";
import { isRecord, type Mapped } from "./common";
import { mapCsaf } from "./csaf";
import { mapOsv } from "./osv";
import { mapStix } from "./stix";

export const MEDIA_TYPES: Record<string, IngestFormat> = {
  "application/json": "native",
  "application/vnd.threatsieve.ingest+json": "native",
  "application/stix+json": "stix",
  "application/vnd.oasis.stix+json": "stix",
  "application/csaf+json": "csaf",
  "application/vnd.oasis.csaf+json": "csaf",
  "application/osv+json": "osv",
  "application/vnd.osv+json": "osv",
};

export interface IngestRequest {
  format: IngestFormat;
  /** Collections are processed asynchronously; a single document is not. */
  batch: boolean;
  defaultTlp?: TlpInput;
  documents: unknown[];
}

const tooMany = () =>
  new AppError(
    "TOO_MANY_ITEMS",
    413,
    "A request accepts at most " + INGEST_MAX_ITEMS + " items",
  );

export function mediaFormat(contentType: string | undefined): IngestFormat {
  const media = contentType?.split(";")[0]?.trim().toLowerCase() ?? "";
  const format = MEDIA_TYPES[media];
  if (!format)
    throw new AppError(
      "UNSUPPORTED_MEDIA_TYPE",
      415,
      "Send one of: " + Object.keys(MEDIA_TYPES).join(", "),
    );
  return format;
}
/**
 * Chooses the format from the Content-Type, or from the `format` field of a
 * JSON envelope, and splits the body into documents of that format.
 */
export function readIngestRequest(
  contentType: string | undefined,
  body: unknown,
): IngestRequest {
  const format = mediaFormat(contentType);
  if (format === "native") {
    if (Array.isArray(body)) {
      if (body.length > INGEST_MAX_ITEMS) throw tooMany();
      if (!body.length)
        throw new AppError("EMPTY_BATCH", 400, "The batch contains no items");
      return { format, batch: true, documents: body };
    }
    if (isRecord(body) && ("items" in body || "format" in body)) {
      if (Array.isArray(body.items) && body.items.length > INGEST_MAX_ITEMS)
        throw tooMany();
      const envelope = IngestEnvelope.parse(body);
      return {
        format: envelope.format,
        batch: true,
        defaultTlp: envelope.default_tlp,
        documents: envelope.items,
      };
    }
    return { format, batch: false, documents: [body] };
  }
  if (format === "stix") return { format, batch: true, documents: [body] };
  if (Array.isArray(body)) {
    if (body.length > INGEST_MAX_ITEMS) throw tooMany();
    if (!body.length)
      throw new AppError("EMPTY_BATCH", 400, "The batch contains no items");
    return { format, batch: true, documents: body };
  }
  return { format, batch: false, documents: [body] };
}

/** Maps every document to native-shaped items; native items pass through. */
export function mapDocuments(
  request: IngestRequest,
): (Mapped & { document: number })[] {
  const out: (Mapped & { document: number })[] = [];
  request.documents.forEach((document, index) => {
    const mapped: Mapped[] =
      request.format === "stix"
        ? mapStix(document)
        : request.format === "csaf"
          ? mapCsaf(document)
          : request.format === "osv"
            ? mapOsv(document)
            : [{ item: document as Mapped["item"], warnings: [] }];
    for (const m of mapped) out.push({ ...m, document: index });
  });
  if (out.length > INGEST_MAX_ITEMS) throw tooMany();
  return out;
}

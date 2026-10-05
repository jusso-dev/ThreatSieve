import { z } from "zod";
import { parse } from "csv-parse/sync";
import { AssessRequest } from "../../schemas/src/index";
export function parseIndicators(
  text: string,
  format: string,
): z.infer<typeof AssessRequest>[] {
  let rows: unknown[];
  if (format === "csv") {
    rows = z.array(z.unknown()).parse(
      parse(text, {
        columns: true,
        skip_empty_lines: true,
        bom: true,
        relax_column_count: false,
        max_record_size: 16384,
      }),
    );
    rows = rows.map((r) => {
      const row = z
        .object({
          observable: z.string().optional(),
          indicator: z.string().optional(),
          type: z.string().optional(),
        })
        .parse(r);
      return {
        observable: row.observable ?? row.indicator,
        type: row.type || undefined,
      };
    });
  } else if (format === "json") {
    const raw: unknown = JSON.parse(text);
    rows = Array.isArray(raw)
      ? raw
      : z.object({ observables: z.array(z.unknown()) }).parse(raw).observables;
  } else if (format === "stix") {
    const bundle = z
      .object({
        type: z.literal("bundle"),
        objects: z.array(
          z
            .object({
              type: z.string(),
              value: z.string().optional(),
              pattern: z.string().optional(),
            })
            .passthrough(),
        ),
      })
      .parse(JSON.parse(text));
    rows = [];
    for (const o of bundle.objects) {
      if (
        o.value &&
        ["ipv4-addr", "ipv6-addr", "domain-name", "url", "email-addr"].includes(
          o.type,
        )
      )
        rows.push(o.value);
      else if (o.type === "indicator" && o.pattern) {
        const match =
          /^\[(domain-name:value|ipv4-addr:value|ipv6-addr:value|url:value|email-addr:value|file:hashes\.'(?:MD5|SHA-1|SHA-256)') = '((?:[^'\\]|\\.)*)'\]$/.exec(
            o.pattern,
          );
        if (!match)
          throw new Error(
            "Only single-observable equality STIX patterns are accepted",
          );
        rows.push(match[2]!.replace(/\\(['\\])/g, "$1"));
      }
    }
  } else
    rows = text
      .split(/\r?\n/)
      .map((s) => s.trim())
      .filter((s) => s && !s.startsWith("#"));
  if (!rows.length || rows.length > 100000)
    throw new Error("Supply between 1 and 100,000 indicators");
  return rows.map((row) =>
    AssessRequest.parse(typeof row === "string" ? { observable: row } : row),
  );
}

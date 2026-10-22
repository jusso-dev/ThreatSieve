import type { Severity } from "./schema";

type Metrics = Record<string, string>;
function metrics(vector: string): Metrics | null {
  const out: Metrics = {};
  for (const part of vector.replace(/^\(|\)$/g, "").split("/")) {
    const [key, value, extra] = part.split(":");
    if (!key || !value || extra !== undefined || key in out) return null;
    out[key] = value;
  }
  return out;
}
const has = (m: Metrics, spec: Record<string, string[]>) =>
  Object.entries(spec).every(([k, values]) => values.includes(m[k] ?? ""));

const V3: Record<string, string[]> = {
  AV: ["N", "A", "L", "P"],
  AC: ["L", "H"],
  PR: ["N", "L", "H"],
  UI: ["N", "R"],
  S: ["U", "C"],
  C: ["H", "L", "N"],
  I: ["H", "L", "N"],
  A: ["H", "L", "N"],
};
const V2: Record<string, string[]> = {
  AV: ["L", "A", "N"],
  AC: ["H", "M", "L"],
  Au: ["M", "S", "N"],
  C: ["N", "P", "C"],
  I: ["N", "P", "C"],
  A: ["N", "P", "C"],
};
const V4: Record<string, string[]> = {
  AV: ["N", "A", "L", "P"],
  AC: ["L", "H"],
  AT: ["N", "P"],
  PR: ["N", "L", "H"],
  UI: ["N", "P", "A"],
  VC: ["H", "L", "N"],
  VI: ["H", "L", "N"],
  VA: ["H", "L", "N"],
  SC: ["H", "L", "N"],
  SI: ["H", "L", "N"],
  SA: ["H", "L", "N"],
};

/** CVSS v3.1 specification section 7.4 rounding. */
function roundUp(value: number) {
  const n = Math.round(value * 100000);
  return n % 10000 === 0 ? n / 100000 : (Math.floor(n / 10000) + 1) / 10;
}
function v3Score(m: Metrics) {
  const scope = m.S === "C";
  const w = (k: string, table: Record<string, number>) => table[m[k]!]!;
  const cia = { H: 0.56, L: 0.22, N: 0 };
  const iss = 1 - (1 - w("C", cia)) * (1 - w("I", cia)) * (1 - w("A", cia));
  const impact = scope
    ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15)
    : 6.42 * iss;
  const exploitability =
    8.22 *
    w("AV", { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }) *
    w("AC", { L: 0.77, H: 0.44 }) *
    w(
      "PR",
      scope ? { N: 0.85, L: 0.68, H: 0.5 } : { N: 0.85, L: 0.62, H: 0.27 },
    ) *
    w("UI", { N: 0.85, R: 0.62 });
  if (impact <= 0) return 0;
  return roundUp(Math.min((scope ? 1.08 : 1) * (impact + exploitability), 10));
}
function v2Score(m: Metrics) {
  const w = (k: string, table: Record<string, number>) => table[m[k]!]!;
  const cia = { N: 0, P: 0.275, C: 0.66 };
  const impact =
    10.41 * (1 - (1 - w("C", cia)) * (1 - w("I", cia)) * (1 - w("A", cia)));
  const exploitability =
    20 *
    w("AV", { L: 0.395, A: 0.646, N: 1 }) *
    w("AC", { H: 0.35, M: 0.61, L: 0.71 }) *
    w("Au", { M: 0.45, S: 0.56, N: 0.704 });
  const score =
    (0.6 * impact + 0.4 * exploitability - 1.5) * (impact === 0 ? 0 : 1.176);
  return Math.round(score * 10) / 10;
}

/**
 * Checks a CVSS vector against its declared version and computes the base
 * score for v2 and v3.x. v4.0 vectors are validated but not scored here.
 */
export function parseCvssVector(
  version: string,
  vector: string,
): { ok: true; score: number | null } | { ok: false; message: string } {
  if (version === "3.0" || version === "3.1") {
    const prefix = "CVSS:" + version + "/";
    if (!vector.startsWith(prefix))
      return { ok: false, message: "Expected a vector starting " + prefix };
    const m = metrics(vector.slice(prefix.length));
    if (!m || !has(m, V3))
      return { ok: false, message: "Invalid CVSS v3 base metrics" };
    return { ok: true, score: v3Score(m) };
  }
  if (version === "2.0") {
    const m = metrics(vector.replace(/^CVSS:2\.0\//, ""));
    if (!m || !has(m, V2))
      return { ok: false, message: "Invalid CVSS v2 base metrics" };
    return { ok: true, score: v2Score(m) };
  }
  if (!vector.startsWith("CVSS:4.0/"))
    return { ok: false, message: "Expected a vector starting CVSS:4.0/" };
  const m = metrics(vector.slice(9));
  if (!m || !has(m, V4))
    return { ok: false, message: "Invalid CVSS v4 base metrics" };
  return { ok: true, score: null };
}

/** FIRST qualitative bands: v3/v4 have Critical; v2 tops out at High. */
export function cvssSeverity(score: number, version = "3.1"): Severity {
  if (score === 0) return "info";
  if (score < 4) return "low";
  if (score < 7) return "medium";
  if (score < 9 || version === "2.0") return "high";
  return "critical";
}

const VENDOR: Record<string, Severity> = {};
for (const [severity, words] of Object.entries({
  critical: [
    "critical",
    "crit",
    "urgent",
    "emergency",
    "very high",
    "p1",
    "sev1",
  ],
  high: ["high", "important", "severe", "major", "p2", "sev2"],
  medium: [
    "medium",
    "moderate",
    "med",
    "warning",
    "warn",
    "elevated",
    "p3",
    "sev3",
  ],
  low: ["low", "minor", "p4", "sev4"],
  info: [
    "info",
    "informational",
    "information",
    "none",
    "negligible",
    "notice",
    "unimportant",
    "p5",
    "sev5",
  ],
}))
  for (const word of words) VENDOR[word] = severity as Severity;

/**
 * Maps a producer's severity onto the five-point scale. Numbers (and numeric
 * strings) are read as 0–10 scores. Returns null when the value is not
 * recognised, so the caller can fall back to CVSS.
 */
export function mapVendorSeverity(value: string | number): Severity | null {
  const numeric =
    typeof value === "number"
      ? value
      : /^\s*\d+(?:\.\d+)?\s*$/.test(value)
        ? Number(value)
        : null;
  if (numeric !== null)
    return numeric >= 0 && numeric <= 10 ? cvssSeverity(numeric) : null;
  const key = String(value)
    .trim()
    .toLowerCase()
    .replace(/[_-]+/g, " ")
    .replace(/^(?:sev|severity|priority) ?(\d)$/, "sev$1")
    .replace(/\s+/g, " ");
  return VENDOR[key] ?? null;
}

import ipaddr from "ipaddr.js";
import { ObservableType, type Observable } from "../../schemas/src/index";

export async function digest(value: string): Promise<string> {
  return Array.from(
    new Uint8Array(
      await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)),
    ),
    (b) => b.toString(16).padStart(2, "0"),
  ).join("");
}
export function canonicalJson(value: unknown): string {
  if (Array.isArray(value))
    return "[" + value.map(canonicalJson).join(",") + "]";
  if (value !== null && typeof value === "object")
    return (
      "{" +
      Object.entries(value)
        .filter(([, v]) => v !== undefined)
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([k, v]) => JSON.stringify(k) + ":" + canonicalJson(v))
        .join(",") +
      "}"
    );
  return JSON.stringify(value) ?? "null";
}
export function detectType(input: string): ObservableType {
  const value = input.trim();
  if (/^(sha256|sha1|md5|ja3|ja4|asn|certificate):/i.test(value))
    return ObservableType.parse(value.split(":")[0]?.toLowerCase());
  if (/^https?:\/\//i.test(value)) return "url";
  if (/^CVE-\d{4}-\d{4,}$/i.test(value)) return "cve";
  if (/^AS\d+$/i.test(value)) return "asn";
  if (ipaddr.isValid(value))
    return ipaddr.parse(value).kind() === "ipv4" ? "ipv4" : "ipv6";
  if (/^[a-f\d]{64}$/i.test(value)) return "sha256";
  if (/^[a-f\d]{40}$/i.test(value)) return "sha1";
  if (/^[a-f\d]{32}$/i.test(value)) return "md5";
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) return "email";
  if (
    value.includes(".") &&
    !/[\s/:@]/.test(value) &&
    !/^\d+(\.\d+)+$/.test(value)
  )
    return "domain";
  throw new Error("Observable type is ambiguous; provide an explicit type");
}
function domain(value: string): string {
  const ascii = new URL("https://" + value.toLowerCase().replace(/\.$/, ""))
    .hostname;
  if (
    ascii.length > 253 ||
    !ascii
      .split(".")
      .every((label) => /^[a-z\d](?:[a-z\d-]{0,61}[a-z\d])?$/.test(label))
  )
    throw new Error("Invalid domain");
  return ascii;
}
export function normalizeValue(input: string, type: ObservableType): string {
  let value = input.trim();
  if (
    !value ||
    value.length > 8192 ||
    [...value].some(
      (char) => char.charCodeAt(0) < 32 || char.charCodeAt(0) === 127,
    )
  )
    throw new Error("Invalid observable");
  if (
    ["sha256", "sha1", "md5", "ja3", "ja4", "asn", "certificate"].includes(type)
  )
    value = value.replace(new RegExp("^" + type + ":", "i"), "");
  switch (type) {
    case "ipv4":
      if (
        !/^(\d{1,3}\.){3}\d{1,3}$/.test(value) ||
        value
          .split(".")
          .some((s) => (s.length > 1 && s.startsWith("0")) || Number(s) > 255)
      )
        throw new Error("Invalid IPv4 address");
      return value;
    case "ipv6": {
      if (
        value.includes("%") ||
        !ipaddr.isValid(value) ||
        ipaddr.parse(value).kind() !== "ipv6"
      )
        throw new Error("Invalid IPv6 address");
      return ipaddr.parse(value).toString();
    }
    case "domain":
    case "hostname":
      return domain(value);
    case "url": {
      const u = new URL(value);
      if (!["http:", "https:"].includes(u.protocol) || u.username || u.password)
        throw new Error("Only credential-free HTTP(S) URLs are accepted");
      u.hash = "";
      return u.href;
    }
    case "email": {
      const parts = value.split("@");
      if (parts.length !== 2 || !parts[0]) throw new Error("Invalid email");
      return parts[0] + "@" + domain(parts[1]!);
    }
    case "sha256":
    case "sha1":
    case "md5":
    case "ja3": {
      const n = type === "sha256" ? 64 : type === "sha1" ? 40 : 32;
      if (!new RegExp("^[a-fA-F0-9]{" + n + "}$").test(value))
        throw new Error("Invalid " + type);
      return value.toLowerCase();
    }
    case "cve":
      if (!/^CVE-\d{4}-\d{4,}$/i.test(value)) throw new Error("Invalid CVE");
      return value.toUpperCase();
    case "asn": {
      value = value.replace(/^AS/i, "");
      if (
        !/^\d+$/.test(value) ||
        Number(value) > 4294967295 ||
        Number(value) < 1
      )
        throw new Error("Invalid ASN");
      return "AS" + Number(value);
    }
    default:
      return value;
  }
}
export async function normalise(
  input: string,
  explicitType?: ObservableType,
): Promise<Observable> {
  const type = explicitType ?? detectType(input);
  const normalizedValue = normalizeValue(input, type);
  const now = new Date().toISOString();
  return {
    id: "obs_" + (await digest(type + ":" + normalizedValue)),
    type,
    value: input,
    normalizedValue,
    createdAt: now,
    updatedAt: now,
  };
}
export async function entityId(type: string, name: string) {
  return (
    type + "_" + (await digest(name.normalize("NFKC").trim().toLowerCase()))
  );
}
export function aliasKey(value: string) {
  return value.normalize("NFKC").trim().toLowerCase().replace(/\s+/g, " ");
}

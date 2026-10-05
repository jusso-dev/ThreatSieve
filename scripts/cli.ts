#!/usr/bin/env node
import { readFileSync, existsSync } from "node:fs";
import { basename } from "node:path";
async function main() {
  const args = process.argv.slice(2);
  const json = args.includes("--json");
  const positional = args.filter((a) => a !== "--json");
  const [command, value, extra] = positional;
  const base = process.env.THREATSIEVE_URL ?? "http://127.0.0.1:8787";
  let key = process.env.THREATSIEVE_API_KEY;
  if (
    !key &&
    new URL(base).hostname === "127.0.0.1" &&
    existsSync("credentials.local.json")
  )
    key = (
      JSON.parse(readFileSync("credentials.local.json", "utf8")) as {
        apiKey: string;
      }
    ).apiKey;
  if (!key) throw new Error("Set THREATSIEVE_API_KEY");
  let path: string;
  let method = "GET";
  let body: string | undefined;
  let contentType = "application/json";
  switch (command) {
    case "assess":
      if (!value) throw new Error("Provide an observable");
      path = "/v1/assess";
      method = "POST";
      body = JSON.stringify({ observable: value });
      break;
    case "assess-file":
      if (!value) throw new Error("Provide a file");
      {
        const format = value.endsWith(".csv")
          ? "csv"
          : value.endsWith(".stix.json")
            ? "stix"
            : value.endsWith(".json")
              ? "json"
              : "text";
        path = "/v1/uploads?format=" + format;
        body = readFileSync(value, "utf8");
        method = "POST";
        contentType = "text/plain";
      }
      break;
    case "feeds":
      if (value === "sync" && extra) {
        path = "/v1/feeds/" + encodeURIComponent(extra) + "/sync";
        method = "POST";
      } else if (value === "status") path = "/v1/feeds";
      else throw new Error("Use feeds status or feeds sync <source>");
      break;
    case "actor":
      path = "/v1/actors/" + encodeURIComponent(value ?? "");
      break;
    case "attack":
      path = "/v1/attack/techniques/" + encodeURIComponent(value ?? "");
      break;
    case "job":
      path = "/v1/jobs/" + encodeURIComponent(value ?? "");
      break;
    default:
      throw new Error(
        "Usage: threatsieve assess <ioc> | assess-file <file> | feeds sync <source> | feeds status | actor <name> | attack <id> | job <id> [--json]",
      );
  }
  const response = await fetch(base + path, {
    method,
    headers: { Authorization: "Bearer " + key, "Content-Type": contentType },
    body,
    redirect: "error",
    signal: AbortSignal.timeout(90000),
  });
  const result: unknown = await response.json();
  if (!response.ok) throw new Error(JSON.stringify(result));
  if (!json)
    console.log(
      "ThreatSieve · " +
        command +
        (value
          ? " · " + (command === "assess-file" ? basename(value) : value)
          : ""),
    );
  console.log(JSON.stringify(result, null, 2));
}
main().catch((error) => {
  console.error(error instanceof Error ? error.message : "Command failed");
  process.exitCode = 1;
});

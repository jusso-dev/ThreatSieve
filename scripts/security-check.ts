import { execFileSync } from "node:child_process";
import { readFileSync, statSync } from "node:fs";
const files = execFileSync(
  "git",
  ["ls-files", "--cached", "--others", "--exclude-standard", "-z"],
  { encoding: "utf8" },
)
  .split("\0")
  .filter(Boolean);
const findings: string[] = [];
for (const file of files) {
  if (
    file.includes("node_modules/") ||
    file.endsWith("pnpm-lock.yaml") ||
    !statSync(file).isFile()
  )
    continue;
  if (
    /(?:^|\/)(?:\.env(?:\..+)?|\.dev\.vars(?:\..+)?|credentials\.local\.json)$/.test(
      file,
    ) &&
    !file.endsWith(".example")
  )
    findings.push(file + ": secret-bearing file must not be committed");
  const text = readFileSync(file, "utf8");
  const rules: [string, RegExp][] = [
    ["private key", /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/],
    ["GitHub token", /\bgh[pousr]_[A-Za-z0-9]{25,}\b/],
    ["AWS access key", /\bAKIA[0-9A-Z]{16}\b/],
    ["ThreatSieve plaintext key", /\bts_[a-f0-9]{64}\b/],
  ];
  for (const [name, pattern] of rules)
    if (pattern.test(text)) findings.push(file + ": possible " + name);
  if (
    /\.(ts|tsx)$/.test(file) &&
    !file.startsWith("tests/") &&
    file !== "scripts/security-check.ts"
  ) {
    if (
      /dangerouslySetInnerHTML|eval\s*\(|child_process/.test(text) &&
      !file.startsWith("scripts/")
    )
      findings.push(file + ": unsafe runtime primitive");
  }
}
if (findings.length) {
  console.error(findings.join("\n"));
  process.exitCode = 1;
} else
  console.log(
    "Security checks passed for " +
      files.length +
      " repository files. No credential patterns or prohibited runtime primitives found.",
  );

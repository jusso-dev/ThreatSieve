/** Public CI output must contain no tenant data, job identifiers or response bodies. */
import { z } from "zod";
import { alertLabels, probeFailureReason } from "./probe-failure";
async function main() {
  const origin = z.url().parse(process.env.THREATSIEVE_API_ORIGIN);
  if (new URL(origin).protocol !== "https:")
    throw new Error("HTTPS is required");
  const key = process.env.THREATSIEVE_MONITOR_KEY;
  if (!key) throw new Error("THREATSIEVE_MONITOR_KEY is required");
  let failed = false;
  for (const path of ["/health", "/ready", "/v1/ops/status"]) {
    try {
      const res = await fetch(new URL(path, origin), {
        headers: path.startsWith("/v1")
          ? { Authorization: "Bearer " + key }
          : {},
        redirect: "error",
        signal: AbortSignal.timeout(30000),
      });
      if (!res.ok) throw new Error("ProbeHTTP" + res.status);
      if (path === "/v1/ops/status") {
        const report = z
          .object({
            alerts: z.array(
              z.object({
                code: z.string().regex(/^[A-Z_]{1,80}$/),
                severity: z.enum(["critical", "warning"]),
                subject: z.string().optional(),
              }),
            ),
          })
          .parse(await res.json());
        const critical = alertLabels(report.alerts, "critical");
        const warnings = alertLabels(report.alerts, "warning");
        if (critical.length) {
          failed = true;
          console.error(
            "Operational thresholds breached: " + critical.join(", "),
          );
        } else console.log("Operational critical thresholds: clear");
        console.log(
          "Operational warnings: " +
            report.alerts.filter((a) => a.severity === "warning").length +
            (warnings.length ? " (" + warnings.join(", ") + ")" : ""),
        );
      } else console.log(path + ": healthy");
    } catch (error) {
      failed = true;
      console.error(
        path +
          ": probe failed (" +
          probeFailureReason(error) +
          "); inspect the private System health view",
      );
    }
  }
  if (failed) process.exitCode = 1;
}
main().catch(() => {
  console.error("Production health probe configuration is invalid");
  process.exitCode = 1;
});

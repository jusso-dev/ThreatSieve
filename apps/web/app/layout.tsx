import type { Metadata } from "next";
import "./globals.css";
import { Shell } from "@/components/shell";
export const metadata: Metadata = {
  title: {
    default: "Threat Operations · ThreatSieve",
    template: "%s · ThreatSieve",
  },
  description:
    "Evidence-backed threat decisions. Ingest, correlate, classify, prioritise and explain.",
};
export default function Layout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <Shell>{children}</Shell>
      </body>
    </html>
  );
}

"use client";
import { usePermission } from "@/lib/access";
import { useState, useEffect } from "react";
import { Boxes, Check } from "lucide-react";
import { useApi, api } from "@/lib/api";
import { PageHeader, DataState } from "@/components/shell";
import { Button } from "@/components/ui/button";
const fields = [
  "technologies",
  "vendors",
  "products",
  "cloudProviders",
  "operatingSystems",
  "industries",
  "countries",
] as const;
type Environment = Record<(typeof fields)[number], string[]>;
const labels = {
  technologies: "Technologies",
  vendors: "Vendors",
  products: "Products",
  cloudProviders: "Cloud providers",
  operatingSystems: "Operating systems",
  industries: "Industries",
  countries: "Countries",
};
export default function Inventory() {
  const canWrite = usePermission("admin");
  const { data, error, loading } = useApi<Environment>("v1/environment");
  const [form, setForm] = useState<Record<string, string>>({});
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    if (data)
      setForm(Object.fromEntries(fields.map((f) => [f, data[f].join(", ")])));
  }, [data]);
  return (
    <>
      <PageHeader
        eyebrow="CUSTOMER CONTEXT"
        title="Your environment"
        description="Make intelligence relevant to the technologies and assets you actually operate."
      />
      <DataState loading={loading} error={error} />
      {data && (
        <section className="panel" style={{ maxWidth: 850 }}>
          <h2>
            <Boxes size={17} />
            Technology profile
          </h2>
          <p className="panel-subtitle">
            Comma-separated values. Relevance reasons are derived from
            structured matches to this inventory.
          </p>
          <form
            className="inventory-form"
            onSubmit={async (e) => {
              e.preventDefault();
              setBusy(true);
              try {
                await api("v1/environment", {
                  method: "PUT",
                  body: JSON.stringify(
                    Object.fromEntries(
                      fields.map((f) => [
                        f,
                        (form[f] ?? "")
                          .split(",")
                          .map((s) => s.trim())
                          .filter(Boolean),
                      ]),
                    ),
                  ),
                });
                setMessage(
                  "Environment profile saved. New assessments will use the updated context.",
                );
              } catch (error) {
                setMessage(
                  error instanceof Error ? error.message : "Save failed",
                );
              } finally {
                setBusy(false);
              }
            }}
          >
            {fields.map((f) => (
              <div key={f}>
                <label htmlFor={f}>{labels[f]}</label>
                <input
                  id={f}
                  value={form[f] ?? ""}
                  onChange={(e) => setForm({ ...form, [f]: e.target.value })}
                />
              </div>
            ))}
            <div className="full-width modal-actions">
              <Button disabled={busy || !canWrite}>
                <Check size={14} />
                {busy ? "Saving…" : "Save environment"}
              </Button>
            </div>
          </form>
        </section>
      )}
      {message && (
        <div role="status" className="notice">
          {message}
        </div>
      )}
    </>
  );
}

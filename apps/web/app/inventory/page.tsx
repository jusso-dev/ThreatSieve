"use client";
import { usePermission } from "@/lib/access";
import { useState, useEffect } from "react";
import { Boxes, Check, Plus, Trash2 } from "lucide-react";
import { useApi, api } from "@/lib/api";
import { PageHeader, DataState } from "@/components/shell";
import { Button } from "@/components/ui/button";
import {
  EnvironmentSchema,
  type CustomerEnvironment,
  type EnvironmentAsset,
} from "../../../../packages/schemas/src/index";
const fields = [
  "technologies",
  "vendors",
  "products",
  "cloudProviders",
  "operatingSystems",
  "industries",
  "countries",
  "regions",
  "brands",
  "domains",
  "subsidiaries",
  "criticalAssets",
  "software",
  "identityProviders",
  "securityProducts",
  "vips",
  "exposedServices",
] as const;
type FieldKey = (typeof fields)[number];
const labels: Record<FieldKey, string> = {
  technologies: "Technologies",
  vendors: "Vendors",
  products: "Products",
  cloudProviders: "Cloud providers",
  operatingSystems: "Operating systems",
  industries: "Industries",
  countries: "Countries",
  regions: "Regions",
  brands: "Monitored brands",
  domains: "Owned domains",
  subsidiaries: "Subsidiaries",
  criticalAssets: "Critical assets",
  software: "Software",
  identityProviders: "Identity providers",
  securityProducts: "Security products",
  vips: "VIPs (workspace private)",
  exposedServices: "Exposed services",
};
type AssetForm = {
  id: string;
  name: string;
  product: string;
  version: string;
  criticality: EnvironmentAsset["criticality"];
  internetExposed: boolean;
  owner: string;
};
function emptyAsset(): AssetForm {
  return {
    id: "",
    name: "",
    product: "",
    version: "",
    criticality: "medium",
    internetExposed: false,
    owner: "",
  };
}
function toAssetForm(a: EnvironmentAsset): AssetForm {
  return {
    id: a.id,
    name: a.name,
    product: a.product,
    version: a.version ?? "",
    criticality: a.criticality,
    internetExposed: Boolean(a.internetExposed),
    owner: a.owner ?? "",
  };
}
export default function Inventory() {
  const canWrite = usePermission("admin");
  const { data, error, loading } = useApi<CustomerEnvironment>("v1/environment");
  const [form, setForm] = useState<Record<string, string>>({});
  const [assets, setAssets] = useState<AssetForm[]>([]);
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    if (!data) return;
    setForm(
      Object.fromEntries(fields.map((f) => [f, (data[f] ?? []).join(", ")])),
    );
    setAssets((data.assets ?? []).map(toAssetForm));
  }, [data]);
  const updateAsset = (index: number, patch: Partial<AssetForm>) => {
    setAssets((rows) =>
      rows.map((row, i) => (i === index ? { ...row, ...patch } : row)),
    );
  };
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
            Comma-separated values for broad technology tags. Use asset rows
            below for versioned inventory used in exposure claims.
          </p>
          <form
            className="inventory-form"
            onSubmit={async (e) => {
              e.preventDefault();
              setBusy(true);
              try {
                const payload = EnvironmentSchema.parse({
                  ...Object.fromEntries(
                    fields.map((f) => [
                      f,
                      (form[f] ?? "")
                        .split(",")
                        .map((s) => s.trim())
                        .filter(Boolean),
                    ]),
                  ),
                  assets: assets
                    .filter((a) => a.id.trim() && a.product.trim())
                    .map((a) => ({
                      id: a.id.trim(),
                      name: a.name.trim() || a.id.trim(),
                      product: a.product.trim(),
                      ...(a.version.trim()
                        ? { version: a.version.trim() }
                        : {}),
                      criticality: a.criticality,
                      internetExposed: a.internetExposed,
                      ...(a.owner.trim() ? { owner: a.owner.trim() } : {}),
                    })),
                });
                await api("v1/environment", {
                  method: "PUT",
                  body: JSON.stringify(payload),
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
            <div className="full-width" style={{ marginTop: 12 }}>
              <h3 style={{ margin: "8px 0 4px", fontSize: 14 }}>
                Asset inventory
              </h3>
              <p className="panel-subtitle" style={{ marginBottom: 12 }}>
                Repeatable assets with id, product, version, criticality,
                internet exposure and owner. Exposure claims match on product
                and version.
              </p>
              {assets.map((asset, index) => (
                <div
                  key={index}
                  className="inventory-form"
                  style={{
                    marginBottom: 14,
                    paddingBottom: 10,
                    borderBottom: "1px solid var(--border, #e5e7eb)",
                  }}
                >
                  <div>
                    <label htmlFor={`asset-id-${index}`}>Asset id</label>
                    <input
                      id={`asset-id-${index}`}
                      value={asset.id}
                      onChange={(e) =>
                        updateAsset(index, { id: e.target.value })
                      }
                      required
                    />
                  </div>
                  <div>
                    <label htmlFor={`asset-name-${index}`}>Name</label>
                    <input
                      id={`asset-name-${index}`}
                      value={asset.name}
                      onChange={(e) =>
                        updateAsset(index, { name: e.target.value })
                      }
                    />
                  </div>
                  <div>
                    <label htmlFor={`asset-product-${index}`}>Product</label>
                    <input
                      id={`asset-product-${index}`}
                      value={asset.product}
                      onChange={(e) =>
                        updateAsset(index, { product: e.target.value })
                      }
                      required
                    />
                  </div>
                  <div>
                    <label htmlFor={`asset-version-${index}`}>Version</label>
                    <input
                      id={`asset-version-${index}`}
                      value={asset.version}
                      onChange={(e) =>
                        updateAsset(index, { version: e.target.value })
                      }
                    />
                  </div>
                  <div>
                    <label htmlFor={`asset-criticality-${index}`}>
                      Criticality
                    </label>
                    <select
                      id={`asset-criticality-${index}`}
                      value={asset.criticality}
                      onChange={(e) =>
                        updateAsset(index, {
                          criticality: e.target
                            .value as EnvironmentAsset["criticality"],
                        })
                      }
                      style={{ width: "100%" }}
                    >
                      <option value="critical">Critical</option>
                      <option value="high">High</option>
                      <option value="medium">Medium</option>
                      <option value="low">Low</option>
                    </select>
                  </div>
                  <div>
                    <label htmlFor={`asset-owner-${index}`}>Owner</label>
                    <input
                      id={`asset-owner-${index}`}
                      value={asset.owner}
                      onChange={(e) =>
                        updateAsset(index, { owner: e.target.value })
                      }
                    />
                  </div>
                  <div>
                    <label htmlFor={`asset-exposed-${index}`}>
                      Internet exposed
                    </label>
                    <input
                      id={`asset-exposed-${index}`}
                      type="checkbox"
                      checked={asset.internetExposed}
                      onChange={(e) =>
                        updateAsset(index, {
                          internetExposed: e.target.checked,
                        })
                      }
                      style={{ width: "auto" }}
                    />
                  </div>
                  <div
                    className="full-width"
                    style={{ display: "flex", justifyContent: "flex-end" }}
                  >
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      disabled={!canWrite}
                      onClick={() =>
                        setAssets((rows) => rows.filter((_, i) => i !== index))
                      }
                    >
                      <Trash2 size={14} />
                      Remove asset
                    </Button>
                  </div>
                </div>
              ))}
              <Button
                type="button"
                variant="outline"
                disabled={!canWrite}
                onClick={() => setAssets((rows) => [...rows, emptyAsset()])}
              >
                <Plus size={14} />
                Add asset
              </Button>
            </div>
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

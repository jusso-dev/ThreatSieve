"use client";
import { useState, useEffect } from "react";
import { Upload, ArrowRight, FileText, CheckCircle2 } from "lucide-react";
import { api } from "@/lib/api";
import { PageHeader } from "@/components/shell";
import { Button } from "@/components/ui/button";
interface Job {
  id: string;
  status: string;
  result: string | null;
  stages: { stage: string; status: string; count: number }[];
}
export default function Bulk() {
  const [text, setText] = useState("");
  const [file, setFile] = useState<File>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [jobId, setJobId] = useState("");
  const [job, setJob] = useState<Job>();
  useEffect(() => {
    if (!jobId) return;
    const refresh = () => {
      void api<Job>("v1/jobs/" + jobId)
        .then(setJob)
        .catch((e) => setError(String(e)));
    };
    refresh();
    const timer = setInterval(refresh, 3000);
    return () => clearInterval(timer);
  }, [jobId]);
  const submit = async (useFile: boolean) => {
    setBusy(true);
    setError("");
    try {
      const format = useFile
        ? file?.name.endsWith(".csv")
          ? "csv"
          : file?.name.endsWith(".stix.json")
            ? "stix"
            : file?.name.endsWith(".json")
              ? "json"
              : "text"
        : "text";
      if (useFile && !file) throw new Error("Select a file");
      if (file && file.size > 16 * 1024 * 1024)
        throw new Error("Files must be 16 MiB or smaller");
      const body = useFile ? await file!.text() : text;
      const result = await api<{ job_id: string }>(
        "v1/uploads?format=" + format,
        { method: "POST", headers: { "Content-Type": "text/plain" }, body },
      );
      setJobId(result.job_id);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Upload failed");
    } finally {
      setBusy(false);
    }
  };
  return (
    <>
      <PageHeader
        eyebrow="BULK ANALYSIS"
        title="From indicators to intelligence."
        description="Normalise, deduplicate and assess large batches through the asynchronous pipeline."
      />
      <div className="bulk-grid">
        <section className="panel">
          <h2>
            <FileText size={16} />
            Paste indicators
          </h2>
          <p className="panel-subtitle">
            One observable per line. Domains, IP addresses, URLs, hashes and
            CVEs.
          </p>
          <textarea
            aria-label="Indicators to analyse"
            className="bulk-textarea"
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder={"example.com\n192.0.2.10\nCVE-2024-3400"}
          />
          <div className="modal-actions">
            <span
              className="muted"
              style={{ marginRight: "auto", fontSize: 11 }}
            >
              {text.split("\n").filter((v) => v.trim()).length} lines
            </span>
            <Button
              disabled={busy || !text.trim()}
              onClick={() => void submit(false)}
            >
              {busy ? "Uploading…" : "Analyse indicators"}
              <ArrowRight size={15} />
            </Button>
          </div>
        </section>
        <section className="panel">
          <h2>
            <Upload size={16} />
            Upload a file
          </h2>
          <p className="panel-subtitle">
            CSV, JSON, plain text or STIX 2.1 single-observable patterns.
          </p>
          <label className="upload-zone">
            <Upload size={30} />
            <strong>Select your intelligence file</strong>
            <span>Up to 100,000 indicators · Maximum 16 MiB</span>
            <input
              type="file"
              accept=".csv,.json,.txt"
              onChange={(e) => setFile(e.target.files?.[0])}
            />
          </label>
          <div className="modal-actions">
            <Button
              variant="outline"
              disabled={busy || !file}
              onClick={() => void submit(true)}
            >
              Upload & analyse
              <ArrowRight size={15} />
            </Button>
          </div>
        </section>
      </div>
      {error && (
        <div role="alert" className="notice text-red">
          {error}
        </div>
      )}
      {job && (
        <section className="panel job-progress">
          <h2>
            <CheckCircle2 size={16} />
            Pipeline progress
          </h2>
          <div className="detail-row">
            <span>Import job</span>
            <strong className="mono">{job.id}</strong>
          </div>
          {job.stages.map((s) => (
            <div className="detail-row" key={s.stage + s.status}>
              <span>
                {s.stage} · {s.status}
              </span>
              <strong>{s.count.toLocaleString()}</strong>
            </div>
          ))}
          <p className="tooltip-note">
            Import completion and classification completion are tracked
            separately. This view refreshes every three seconds.
          </p>
        </section>
      )}
      <div className="operations-note">
        <CheckCircle2 size={16} />
        <p>
          Duplicates converge to deterministic identities. Unchanged evidence
          reuses cached classifications.
        </p>
      </div>
    </>
  );
}

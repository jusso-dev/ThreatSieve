"use client";
import { usePermission } from "@/lib/access";
import { toast } from "sonner";
import { useState, useEffect, useRef } from "react";
import { Upload, ArrowRight, FileText, CheckCircle2 } from "lucide-react";
import { api } from "@/lib/api";
import { PageHeader } from "@/components/shell";
import { Button } from "@/components/ui/button";
interface Job {
  id: string;
  status: string;
  pipeline_status: "running" | "failed" | "complete";
  totals: { processed: number; rejected: number };
  result: string | null;
  stages: { stage: string; status: string; count: number }[];
}
export default function Bulk() {
  const canWrite = usePermission("assessment:write");
  const [text, setText] = useState("");
  const [file, setFile] = useState<File>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [jobId, setJobId] = useState("");
  const [job, setJob] = useState<Job>();
  const [pollVersion, setPollVersion] = useState(0);
  const submission = useRef<{
    body: string;
    format: string;
    key: string;
  } | null>(null);
  useEffect(() => {
    if (!jobId) return;
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const refresh = async () => {
      try {
        const result = await api<Job>("v1/jobs/" + jobId, {
          signal: controller.signal,
        });
        if (controller.signal.aborted) return;
        setJob(result);
        setError("");
        if (result.pipeline_status === "complete")
          toast.success(
            "Import complete. Your indicators are ready to investigate.",
            { id: "import:" + jobId },
          );
        if (result.pipeline_status === "failed")
          toast.error(
            "Some indicators couldn’t be processed. Review the import details below.",
            { id: "import:" + jobId },
          );
        if (result.pipeline_status === "running")
          timer = setTimeout(() => void refresh(), 3000);
      } catch (e) {
        if (!controller.signal.aborted)
          setError(
            e instanceof Error
              ? e.message
              : "Could not refresh import progress",
          );
      }
    };
    void refresh();
    return () => {
      controller.abort();
      clearTimeout(timer);
    };
  }, [jobId, pollVersion]);
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
      const invalid = (message: string): never => {
        toast.error(message);
        throw new Error(message);
      };
      if (useFile && !file) invalid("Select a file to upload.");
      if (useFile && file && file.size > 16 * 1024 * 1024)
        invalid("Files must be 16 MiB or smaller.");
      const body = useFile ? await file!.text() : text;
      if (new Blob([body]).size > 16 * 1024 * 1024)
        invalid("Indicators must be 16 MiB or smaller.");
      if (
        !submission.current ||
        submission.current.body !== body ||
        submission.current.format !== format
      )
        submission.current = { body, format, key: crypto.randomUUID() };
      const result = await api<{ job_id: string }>(
        "v1/uploads?format=" + format,
        {
          method: "POST",
          headers: {
            "Content-Type": "text/plain",
            "Idempotency-Key": submission.current.key,
          },
          body,
        },
      );
      setJob(undefined);
      setJobId(result.job_id);
      submission.current = null;
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
        title="Bulk analysis"
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
              disabled={!canWrite || busy || !text.trim()}
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
              disabled={!canWrite || busy || !file}
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
          {jobId && (
            <Button
              variant="outline"
              onClick={() => setPollVersion((v) => v + 1)}
            >
              Retry progress refresh
            </Button>
          )}
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
          <div role="status" className="notice">
            {job.pipeline_status === "complete"
              ? "Analysis complete"
              : job.pipeline_status === "failed"
                ? "Analysis finished with failed jobs. Review operational errors before using the results."
                : "Analysis in progress"}
          </div>
          <div className="detail-row">
            <span>Indicators processed</span>
            <strong>{job.totals.processed.toLocaleString()}</strong>
          </div>
          <div className="detail-row">
            <span>Invalid indicators</span>
            <strong>{job.totals.rejected.toLocaleString()}</strong>
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
            separately. Progress refreshes while jobs are running.
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

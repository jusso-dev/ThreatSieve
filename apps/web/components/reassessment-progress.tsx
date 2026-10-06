"use client";
import Link from "next/link";
import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { Button } from "./ui/button";

export function ReassessmentProgress({ jobId }: { jobId: string }) {
  const [state, setState] = useState<{
    message: string;
    assessmentId?: string;
    retry?: boolean;
  }>({
    message:
      "Reassessment queued. We’ll show a link when the new decision is ready.",
  });
  const [retry, setRetry] = useState(0);
  useEffect(() => {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout>;
    let checks = 0;
    const check = async () => {
      try {
        const job = await api<{ status: string; result: string | null }>(
          "v1/jobs/" + encodeURIComponent(jobId),
          { signal: controller.signal },
        );
        if (controller.signal.aborted) return;
        if (job.status === "complete") {
          const result: unknown =
            typeof job.result === "string"
              ? JSON.parse(job.result)
              : job.result;
          const id =
            result &&
            typeof result === "object" &&
            "assessmentId" in result &&
            typeof result.assessmentId === "string"
              ? result.assessmentId
              : undefined;
          setState({
            message: id
              ? "Reassessment complete. The original decision remains available for comparison."
              : "Processing finished. Refresh your threat operations queue to see the latest decision.",
            assessmentId: id,
          });
          return;
        }
        if (job.status === "failed") {
          setState({
            message:
              "Reassessment could not finish. Your original assessment is unchanged. Ask an administrator to inspect the failed job.",
          });
          return;
        }
        if (++checks >= 40) {
          setState({
            message:
              "Reassessment is still processing. You can check its status again or continue investigating.",
            retry: true,
          });
          return;
        }
        timer = setTimeout(() => void check(), 3000);
      } catch {
        if (!controller.signal.aborted)
          setState({
            message:
              "We couldn’t check reassessment progress. Your request may still be processing.",
            retry: true,
          });
      }
    };
    void check();
    return () => {
      controller.abort();
      clearTimeout(timer);
    };
  }, [jobId, retry]);
  return (
    <div className="notice reassessment-progress" role="status">
      <p>{state.message}</p>
      {state.assessmentId && (
        <Link
          className="text-link"
          href={"/investigations/" + encodeURIComponent(state.assessmentId)}
        >
          Open updated assessment →
        </Link>
      )}
      {state.retry && (
        <Button
          variant="outline"
          size="sm"
          onClick={() => {
            setState({ message: "Checking reassessment progress…" });
            setRetry((v) => v + 1);
          }}
        >
          Check status
        </Button>
      )}
    </div>
  );
}

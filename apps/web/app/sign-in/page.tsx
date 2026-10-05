"use client";
import { useState } from "react";
import { useRouter } from "next/navigation";
import { ShieldCheck, ArrowRight } from "lucide-react";
import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
export default function SignIn() {
  const [key, setKey] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const router = useRouter();
  return (
    <main className="sign-in">
      <section className="sign-in-card">
        <div className="brand">
          <ShieldCheck size={26} />
          ThreatSieve<span className="brand-period">.</span>
        </div>
        <h1>Enter your workspace.</h1>
        <p>Evidence-backed intelligence starts here.</p>
        <form
          onSubmit={async (e) => {
            e.preventDefault();
            setBusy(true);
            try {
              await api("v1/session", {
                method: "POST",
                headers: { Authorization: "Bearer " + key },
              });
              setKey("");
              router.push("/");
            } catch (e) {
              setError(e instanceof Error ? e.message : "Sign-in failed");
            } finally {
              setBusy(false);
            }
          }}
        >
          <label htmlFor="api-key">Workspace API key</label>
          <input
            id="api-key"
            type="password"
            autoComplete="off"
            required
            value={key}
            onChange={(e) => setKey(e.target.value)}
            placeholder="ts_…"
          />
          {error && (
            <p className="text-red" role="alert" style={{ marginBottom: 14 }}>
              {error}
            </p>
          )}
          <Button disabled={busy}>
            {busy ? "Connecting…" : "Continue securely"}
            <ArrowRight size={15} />
          </Button>
        </form>
        <p className="sign-in-note">
          Your key is exchanged for a secure, time-limited session. It is never
          stored in browser storage.
        </p>
      </section>
    </main>
  );
}

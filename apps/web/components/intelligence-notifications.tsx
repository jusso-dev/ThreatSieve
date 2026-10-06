"use client";
import Link from "next/link";
import { Bell } from "lucide-react";
import { useState } from "react";
import { api, useApi } from "@/lib/api";
import { Modal } from "./ui/modal";
import { DataState } from "./shell";
import { Button } from "./ui/button";
import { relativeTime } from "@/lib/utils";
import { workspaces } from "@/lib/workspace";
import type { WorkKind } from "../../../packages/schemas/src/enterprise";
export function Notifications() {
  const [open, setOpen] = useState(false);
  return (
    <>
      <button
        className="icon-button"
        aria-label="Open intelligence notifications"
        onClick={() => setOpen(true)}
      >
        <Bell size={17} />
      </button>
      {open && <NotificationList onClose={() => setOpen(false)} />}
    </>
  );
}
function NotificationList({ onClose }: { onClose: () => void }) {
  const { data, error, loading, reload } = useApi<{
    data: {
      id: string;
      object_id: string;
      objectType: WorkKind;
      entity_id: string | null;
      reason: string;
      read_at: string | null;
      created_at: string;
    }[];
  }>("v1/notifications");
  return (
    <Modal titleId="notification-title" onClose={onClose}>
      <div className="section-title">
        <h2 id="notification-title">Intelligence notifications</h2>
        <Button variant="ghost" size="sm" onClick={() => void reload()}>
          Refresh
        </Button>
      </div>
      <DataState loading={loading} error={error} />
      <div className="notification-list">
        {data?.data.map((n) => (
          <article key={n.id} className={n.read_at ? "read" : "unread"}>
            <Link
              onClick={onClose}
              href={"/" + workspaces[n.objectType].path + "/" + n.object_id}
            >
              {n.reason}
            </Link>
            <small>{relativeTime(n.created_at)}</small>
            {n.entity_id && (
              <Link onClick={onClose} href={"/intelligence/" + n.entity_id}>
                Inspect intelligence
              </Link>
            )}
            {!n.read_at && (
              <Button
                variant="ghost"
                size="sm"
                onClick={async () => {
                  try {
                    await api(
                      "v1/notifications/" + encodeURIComponent(n.id) + "/read",
                      { method: "POST" },
                    );
                    await reload();
                  } catch {
                    // The API helper reports the error; keep the notification available to retry.
                  }
                }}
              >
                Mark read
              </Button>
            )}
          </article>
        ))}
      </div>
      {data && !data.data.length && (
        <p className="muted">
          No notifications. Matches and automation events will appear here.
        </p>
      )}
    </Modal>
  );
}

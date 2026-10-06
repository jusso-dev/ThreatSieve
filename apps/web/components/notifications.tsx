"use client";
import { Toaster } from "sonner";
export function Notifications() {
  return (
    <Toaster
      position="bottom-right"
      richColors
      closeButton
      duration={6000}
      toastOptions={{ className: "notification" }}
    />
  );
}

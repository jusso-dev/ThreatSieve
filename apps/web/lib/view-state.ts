"use client";
import { usePathname, useSearchParams } from "next/navigation";
import { toast } from "sonner";

/** URL-backed filters survive reloads, bookmarks and browser back navigation. */
export function useViewState() {
  const params = useSearchParams();
  const pathname = usePathname();
  const update = (changes: Record<string, string>, replace = false) => {
    const next = new URLSearchParams(params.toString());
    next.delete("cursor");
    for (const [key, value] of Object.entries(changes)) {
      if (value) next.set(key, value);
      else next.delete(key);
    }
    window.history[replace ? "replaceState" : "pushState"](
      null,
      "",
      pathname + (next.size ? "?" + next.toString() : ""),
    );
  };
  return { params, update };
}

export async function copyText(text: string, message = "Copied to clipboard.") {
  try {
    await navigator.clipboard.writeText(text);
    toast.success(message);
  } catch {
    toast.error(
      "Clipboard access was blocked. Select the text and copy it manually.",
    );
  }
}

export function defang(value: string) {
  return value
    .replace(/^https:/i, "hxxps:")
    .replace(/^http:/i, "hxxp:")
    .replaceAll(".", "[.]")
    .replaceAll("@", "[@]");
}

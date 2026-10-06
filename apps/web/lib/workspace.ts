import type { WorkKind } from "../../../packages/schemas/src/enterprise";
export const workspaces: Record<
  WorkKind,
  {
    path: string;
    title: string;
    singular: string;
    description: string;
    statuses: string[];
  }
> = {
  requirement: {
    path: "requirements",
    title: "Intelligence requirements",
    singular: "requirement",
    description: "Define the questions that direct collection and analysis.",
    statuses: ["draft", "active", "review", "closed"],
  },
  investigation: {
    path: "cases",
    title: "Investigations",
    singular: "investigation",
    description:
      "Develop hypotheses, assemble evidence and record analyst judgement.",
    statuses: ["open", "in-progress", "waiting", "review", "closed"],
  },
  watchlist: {
    path: "watchlists",
    title: "Watchlists",
    singular: "watchlist",
    description: "Monitor a defined set of entities and collection criteria.",
    statuses: ["active", "paused", "closed"],
  },
  collection: {
    path: "collections",
    title: "Collections",
    singular: "collection",
    description:
      "Curate intelligence for a defined purpose and controlled distribution.",
    statuses: ["draft", "published", "archived"],
  },
  report: {
    path: "reports",
    title: "Reports",
    singular: "report",
    description: "Author intelligence with references to original evidence.",
    statuses: ["draft", "review", "published", "archived"],
  },
  playbook: {
    path: "automations",
    title: "Automation",
    singular: "playbook",
    description: "Run bounded, auditable actions when intelligence changes.",
    statuses: ["paused", "active"],
  },
};
export const workApi = (kind: WorkKind) =>
  kind === "investigation"
    ? "investigations"
    : kind === "playbook"
      ? "playbooks"
      : workspaces[kind].path;
export const splitValues = (v: string) =>
  v
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);

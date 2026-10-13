# GATES

Orchestrated build. Real gates live in `gates/`:

- `gates/root.md` — overall acceptance (full suite, typecheck, lint, e2e, finding→evidence map)
- `gates/node-1.1.md` … `gates/node-1.4.md` — branch integration gates
- `gates/leaf-1.1.1.md` … `gates/leaf-1.4.3.md` — per-leaf acceptance

Plan and contracts: `PLAN.md` (contract fixed before fan-out; status log appended per leaf).

Run: `node /Users/justinmiddler/.agents/skills/unlazy/scripts/gate-check.mjs gates/<file>.md`

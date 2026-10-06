/** Explicit boundaries preserve compound SQLite statements such as triggers. */
export function migrationStatements(sql: string): string[] {
  return sql
    .split(
      sql.includes("-- statement-breakpoint") ? "-- statement-breakpoint" : ";",
    )
    .map((s) => s.trim())
    .filter(Boolean);
}

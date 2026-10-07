import {
  customType,
  integer,
  sqliteTable,
  text,
} from "drizzle-orm/sqlite-core";
// Existing ThreatSieve records use ISO timestamps; preserve that representation.
const date = customType<{ data: Date; driverData: string }>({
  dataType: () => "text",
  toDriver: (value) => value.toISOString(),
  fromDriver: (value) => new Date(value),
});
const timestamps = () => ({
  createdAt: date("created_at").notNull(),
  updatedAt: date("updated_at").notNull(),
});
export const user = sqliteTable("users", {
  id: text("id").primaryKey(),
  email: text("email").notNull().unique(),
  name: text("name").notNull(),
  emailVerified: integer("email_verified", { mode: "boolean" }).notNull(),
  image: text("image"),
  twoFactorEnabled: integer("two_factor_enabled", { mode: "boolean" }).default(
    false,
  ),
  ...timestamps(),
});
export const twoFactor = sqliteTable("auth_two_factor", {
  id: text("id").primaryKey(),
  userId: text("user_id").notNull().unique(),
  secret: text("secret").notNull(),
  backupCodes: text("backup_codes").notNull(),
  verified: integer("verified", { mode: "boolean" }).default(false),
  failedVerificationCount: integer("failed_verification_count").default(0),
  lockedUntil: date("locked_until"),
});
export const session = sqliteTable("auth_sessions", {
  id: text("id").primaryKey(),
  token: text("token").notNull().unique(),
  userId: text("user_id").notNull(),
  expiresAt: date("expires_at").notNull(),
  ipAddress: text("ip_address"),
  userAgent: text("user_agent"),
  activeOrganizationId: text("active_organization_id"),
  ...timestamps(),
});
export const account = sqliteTable("auth_accounts", {
  id: text("id").primaryKey(),
  accountId: text("account_id").notNull(),
  providerId: text("provider_id").notNull(),
  userId: text("user_id").notNull(),
  accessToken: text("access_token"),
  refreshToken: text("refresh_token"),
  idToken: text("id_token"),
  accessTokenExpiresAt: date("access_token_expires_at"),
  refreshTokenExpiresAt: date("refresh_token_expires_at"),
  scope: text("scope"),
  password: text("password"),
  ...timestamps(),
});
export const verification = sqliteTable("auth_verifications", {
  id: text("id").primaryKey(),
  identifier: text("identifier").notNull(),
  value: text("value").notNull(),
  expiresAt: date("expires_at").notNull(),
  ...timestamps(),
});
export const rateLimit = sqliteTable("auth_rate_limits", {
  id: text("id").primaryKey(),
  key: text("key").notNull().unique(),
  count: integer("count").notNull(),
  lastRequest: integer("last_request").notNull(),
});
export const organization = sqliteTable("tenants", {
  id: text("id").primaryKey(),
  name: text("name").notNull(),
  slug: text("slug").unique(),
  logo: text("logo"),
  metadata: text("metadata"),
  createdAt: date("created_at").notNull(),
});
export const member = sqliteTable("tenant_members", {
  id: text("id").primaryKey(),
  organizationId: text("tenant_id").notNull(),
  userId: text("user_id").notNull(),
  role: text("role").notNull(),
  createdAt: date("created_at").notNull(),
});
export const invitation = sqliteTable("auth_invitations", {
  id: text("id").primaryKey(),
  organizationId: text("organization_id").notNull(),
  email: text("email").notNull(),
  role: text("role").notNull(),
  status: text("status").notNull(),
  inviterId: text("inviter_id").notNull(),
  expiresAt: date("expires_at").notNull(),
  createdAt: date("created_at").notNull(),
});

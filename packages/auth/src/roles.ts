import { createAccessControl } from "better-auth/plugins/access";
import { defaultStatements } from "better-auth/plugins/organization/access";
export const ac = createAccessControl(defaultStatements);
export const roles = {
  admin: ac.newRole({
    organization: ["update"],
    member: ["create", "update", "delete"],
    invitation: ["create", "cancel"],
  }),
  analyst: ac.newRole({}),
  viewer: ac.newRole({}),
};

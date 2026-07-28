import { apiFetch } from "./client";

/**
 * POST /acl/grant
 *
 * Grants access to a specific resource for another user.
 */
export async function grantAccess(
  resource_type: string,
  resource_id: string,
  grantee_email: string,
  permissions: string
): Promise<any> {
  return await apiFetch("/acl/grant", {
    method: "POST",
    body: {
      resource_type,
      resource_id,
      grantee_email,
      permissions
    }
  });
}

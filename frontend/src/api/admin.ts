/**
 * Contract §6 — Administration, and §7 — platform security policy.
 *
 * `PATCH /admin/users/{id}/role` and `/status` accept either a query parameter
 * or a JSON body (contract §6). The query-parameter form is used here because it
 * is the variant the contract documents inline (`?role=`, `?is_active=`).
 */

import { API_PREFIX, apiRequest, toPage } from './client';
import type {
  AdminMutationAck,
  AdminStats,
  AdminUser,
  AuditChainVerifyResult,
  AuditLogEntry,
  AuditLogFilters,
  Page,
  PageParams,
  SecurityPolicy,
  UserRole,
} from '../types';

const ADMIN = `${API_PREFIX}/admin`;

/** `GET /admin/users` — paged users plus lockout/login telemetry. */
export async function listUsers(
  params: PageParams = {},
  signal?: AbortSignal,
): Promise<Page<AdminUser>> {
  const limit = params.limit ?? 25;
  const payload = await apiRequest<Page<AdminUser> | AdminUser[]>(`${ADMIN}/users`, {
    query: { limit, cursor: params.cursor },
    signal,
  });
  return toPage(payload, limit);
}

/** `PATCH /admin/users/{id}/role` — self-demotion is rejected with `400`. */
export function updateUserRole(userId: string, role: UserRole): Promise<AdminMutationAck> {
  return apiRequest<AdminMutationAck>(`${ADMIN}/users/${encodeURIComponent(userId)}/role`, {
    method: 'PATCH',
    query: { role },
  });
}

/** `PATCH /admin/users/{id}/status` — self-disable is rejected with `400`. */
export function updateUserStatus(userId: string, isActive: boolean): Promise<AdminMutationAck> {
  return apiRequest<AdminMutationAck>(`${ADMIN}/users/${encodeURIComponent(userId)}/status`, {
    method: 'PATCH',
    query: { is_active: isActive },
  });
}

/** `POST /admin/users/{id}/unlock` — clears lockout and failed attempts. */
export function unlockUser(userId: string): Promise<AdminMutationAck> {
  return apiRequest<AdminMutationAck>(`${ADMIN}/users/${encodeURIComponent(userId)}/unlock`, {
    method: 'POST',
  });
}


/** `POST /admin/users/{id}/revoke-sessions` — revoke all refresh sessions. */
export function revokeUserSessions(userId: string): Promise<AdminMutationAck> {
  return apiRequest<AdminMutationAck>(`${ADMIN}/users/${encodeURIComponent(userId)}/revoke-sessions`, {
    method: 'POST',
  });
}

/** `GET /admin/audit-logs` — paged, filtered browser. */
export async function listAuditLogs(
  filters: AuditLogFilters = {},
  signal?: AbortSignal,
): Promise<Page<AuditLogEntry>> {
  const limit = filters.limit ?? 25;
  const payload = await apiRequest<Page<AuditLogEntry> | AuditLogEntry[]>(`${ADMIN}/audit-logs`, {
    query: {
      limit,
      cursor: filters.cursor,
      action: filters.action,
      actor_id: filters.actor_id,
      outcome: filters.outcome,
      from: filters.from,
      to: filters.to,
    },
    signal,
  });
  return toPage(payload, limit);
}

/** `GET /admin/audit-logs/verify` — walks the hash chain. */
export function verifyAuditChain(): Promise<AuditChainVerifyResult> {
  return apiRequest<AuditChainVerifyResult>(`${ADMIN}/audit-logs/verify`);
}

/** `GET /admin/security-policy` — effective, read-only platform policy. */
export function getSecurityPolicy(signal?: AbortSignal): Promise<SecurityPolicy> {
  return apiRequest<SecurityPolicy>(`${ADMIN}/security-policy`, { signal });
}

/** `GET /admin/stats` */
export function getAdminStats(signal?: AbortSignal): Promise<AdminStats> {
  return apiRequest<AdminStats>(`${ADMIN}/stats`, { signal });
}

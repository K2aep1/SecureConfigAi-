/**
 * Contract §5 — Baseline pack, policy overrides, resolved control set and
 * per-device exemptions.
 */

import { API_PREFIX, apiRequest, toPage } from './client';
import type {
  BaselinePack,
  EffectiveControl,
  EffectivePoliciesResponse,
  Exemption,
  ExemptionCreateRequest,
  Page,
  Policy,
  PolicyCreateRequest,
  PolicyListParams,
  PolicyUpdateRequest,
} from '../types';

const POLICIES = `${API_PREFIX}/policies`;
const BASELINE = `${API_PREFIX}/baseline`;
const DEVICES = `${API_PREFIX}/devices`;

/** `GET /baseline` — the shipped baseline pack (single object, not paged). */
export function getBaseline(signal?: AbortSignal): Promise<BaselinePack> {
  return apiRequest<BaselinePack>(BASELINE, { signal });
}

/** `GET /policies` — overrides; `include_disabled` is contract-documented. */
export async function listPolicies(
  filters: PolicyListParams = {},
  signal?: AbortSignal,
): Promise<Page<Policy>> {
  const limit = filters.limit ?? 25;
  const payload = await apiRequest<Page<Policy> | Policy[]>(POLICIES, {
    query: { limit, cursor: filters.cursor, include_disabled: filters.include_disabled },
    signal,
  });
  return toPage(payload, limit);
}

/** `POST /policies` (admin) → `201`. */
export function createPolicy(request: PolicyCreateRequest): Promise<Policy> {
  return apiRequest<Policy>(POLICIES, { method: 'POST', body: request });
}

/** `GET /policies/{id}` */
export function getPolicy(policyId: string, signal?: AbortSignal): Promise<Policy> {
  return apiRequest<Policy>(`${POLICIES}/${encodeURIComponent(policyId)}`, { signal });
}

/** `PUT /policies/{id}` (admin) — partial update; never silently re-enables. */
export function updatePolicy(policyId: string, request: PolicyUpdateRequest): Promise<Policy> {
  return apiRequest<Policy>(`${POLICIES}/${encodeURIComponent(policyId)}`, {
    method: 'PUT',
    body: request,
  });
}

/** `PATCH /policies/{id}/toggle` (admin) — flips and returns the new state. */
export function togglePolicy(policyId: string): Promise<Policy> {
  return apiRequest<Policy>(`${POLICIES}/${encodeURIComponent(policyId)}/toggle`, {
    method: 'PATCH',
  });
}

/** `DELETE /policies/{id}` (admin) → `204`. */
export function deletePolicy(policyId: string): Promise<void> {
  return apiRequest<void>(`${POLICIES}/${encodeURIComponent(policyId)}`, { method: 'DELETE' });
}

/**
 * `GET /policies/effective` (admin) — the resolved control set, with the
 * baseline values and the layer that supplied each field. A bare array is also
 * accepted defensively, but the documented and implemented envelope is
 * `{baseline_id, baseline_version, total_weight, controls}`.
 */
export async function getEffectivePolicies(
  signal?: AbortSignal,
): Promise<EffectivePoliciesResponse> {
  const payload = await apiRequest<EffectivePoliciesResponse | EffectiveControl[]>(
    `${POLICIES}/effective`,
    { signal },
  );

  if (Array.isArray(payload)) {
    return { baseline_id: '', baseline_version: '', total_weight: 0, controls: payload };
  }
  return {
    baseline_id: payload.baseline_id ?? '',
    baseline_version: payload.baseline_version ?? '',
    total_weight: payload.total_weight ?? 0,
    controls: payload.controls ?? [],
  };
}

/** `GET /devices/{id}/exemptions` — array of exemptions for one device. */
export async function listDeviceExemptions(
  deviceId: string,
  signal?: AbortSignal,
): Promise<Exemption[]> {
  const payload = await apiRequest<Exemption[] | Page<Exemption>>(
    `${DEVICES}/${encodeURIComponent(deviceId)}/exemptions`,
    { signal },
  );
  if (Array.isArray(payload)) return payload;
  return toPage(payload, 25).items;
}

/** `POST /devices/{id}/exemptions` (admin) → `201`. */
export function createDeviceExemption(
  deviceId: string,
  request: ExemptionCreateRequest,
): Promise<Exemption> {
  return apiRequest<Exemption>(`${DEVICES}/${encodeURIComponent(deviceId)}/exemptions`, {
    method: 'POST',
    body: request,
  });
}

/** `DELETE /devices/{id}/exemptions/{control_id}` (admin) → `204`. */
export function deleteDeviceExemption(deviceId: string, controlId: string): Promise<void> {
  return apiRequest<void>(
    `${DEVICES}/${encodeURIComponent(deviceId)}/exemptions/${encodeURIComponent(controlId)}`,
    { method: 'DELETE' },
  );
}

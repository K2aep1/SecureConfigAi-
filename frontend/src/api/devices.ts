/**
 * Contract §4 — Devices.
 */

import { API_PREFIX, apiRequest, toPage } from './client';
import type {
  Device,
  DeviceCompareResponse,
  DeviceListFilters,
  DeviceRegisterRequest,
  DeviceUpdateRequest,
  Page,
} from '../types';

const DEVICES = `${API_PREFIX}/devices`;

/**
 * `GET /devices` — paged `DeviceOut` list.
 * The contract documents only `limit`/`cursor` for this route, so no other
 * query parameter is sent.
 */
export async function listDevices(
  filters: DeviceListFilters = {},
  signal?: AbortSignal,
): Promise<Page<Device>> {
  const limit = filters.limit ?? 25;
  const payload = await apiRequest<Page<Device> | Device[]>(DEVICES, {
    query: { limit, cursor: filters.cursor },
    signal,
  });
  return toPage(payload, limit);
}

/** `POST /devices/register` → `201 DeviceOut` (upsert by hostname). */
export function registerDevice(request: DeviceRegisterRequest): Promise<Device> {
  return apiRequest<Device>(`${DEVICES}/register`, { method: 'POST', body: request });
}

/** `GET /devices/{id}` */
export function getDevice(deviceId: string, signal?: AbortSignal): Promise<Device> {
  return apiRequest<Device>(`${DEVICES}/${encodeURIComponent(deviceId)}`, { signal });
}

/** `PUT /devices/{id}` — partial update, including `criticality` (1..5). */
export function updateDevice(deviceId: string, request: DeviceUpdateRequest): Promise<Device> {
  return apiRequest<Device>(`${DEVICES}/${encodeURIComponent(deviceId)}`, {
    method: 'PUT',
    body: request,
  });
}

/** `DELETE /devices/{id}` → `204` (scan history is detached, not deleted). */
export function deleteDevice(deviceId: string): Promise<void> {
  return apiRequest<void>(`${DEVICES}/${encodeURIComponent(deviceId)}`, { method: 'DELETE' });
}

/**
 * `GET /devices/compare` — side-by-side latest posture.
 * The contract documents no query parameters for this route.
 */
export function compareDevices(signal?: AbortSignal): Promise<DeviceCompareResponse> {
  return apiRequest<DeviceCompareResponse>(`${DEVICES}/compare`, { signal });
}

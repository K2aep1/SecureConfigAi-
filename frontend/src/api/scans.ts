/**
 * Contract §3 — Scans.
 *
 * `GET /scans/{id}/document` is deliberately **not** called from any list or
 * detail screen: the evidence drawer is the only caller, so the full stored
 * evidence is fetched only when a user asks to see it (requirement 5).
 */

import { API_PREFIX, apiRequest, apiRequestRaw, toPage } from './client';
import type {
  Page,
  ScanCancelResponse,
  ScanDocument,
  ScanListFilters,
  ScanResults,
  ScanStartRequest,
  ScanStartResponse,
  ScanStatusResponse,
  ScanSummary,
  ScanUploadResponse,
} from '../types';

const SCANS = `${API_PREFIX}/scans`;

/** `POST /scans/start` → `202` immediately; never awaits a finished scan. */
export function startScan(request: ScanStartRequest): Promise<ScanStartResponse> {
  return apiRequest<ScanStartResponse>(`${SCANS}/start`, { method: 'POST', body: request });
}

/** `GET /scans` — paged, default order `started_at desc`. */
export async function listScans(
  filters: ScanListFilters = {},
  signal?: AbortSignal,
): Promise<Page<ScanSummary>> {
  const limit = filters.limit ?? 25;
  const payload = await apiRequest<Page<ScanSummary> | ScanSummary[]>(SCANS, {
    query: {
      limit,
      cursor: filters.cursor,
      status: filters.status,
      device_id: filters.device_id,
      source: filters.source,
      q: filters.q,
    },
    signal,
  });
  return toPage(payload, limit);
}

/** `GET /scans/{id}` */
export function getScan(scanId: string, signal?: AbortSignal): Promise<ScanSummary> {
  return apiRequest<ScanSummary>(`${SCANS}/${encodeURIComponent(scanId)}`, { signal });
}

/** `GET /scans/{id}/status` — polled while a scan is queued/running. */
export function getScanStatus(scanId: string, signal?: AbortSignal): Promise<ScanStatusResponse> {
  return apiRequest<ScanStatusResponse>(`${SCANS}/${encodeURIComponent(scanId)}/status`, { signal });
}

/** `POST /scans/{id}/cancel` → `202 {status:"cancelling"}`. */
export function cancelScan(scanId: string): Promise<ScanCancelResponse> {
  return apiRequest<ScanCancelResponse>(`${SCANS}/${encodeURIComponent(scanId)}/cancel`, {
    method: 'POST',
  });
}

/** `GET /scans/{id}/results` — assessment payload without the raw document. */
export function getScanResults(scanId: string, signal?: AbortSignal): Promise<ScanResults> {
  return apiRequest<ScanResults>(`${SCANS}/${encodeURIComponent(scanId)}/results`, { signal });
}

/** `GET /scans/{id}/document` — evidence drawer only. */
export function getScanDocument(scanId: string, signal?: AbortSignal): Promise<ScanDocument> {
  return apiRequest<ScanDocument>(`${SCANS}/${encodeURIComponent(scanId)}/document`, { signal });
}

/**
 * `GET /scans/{id}/report/html` — `text/html` with `ETag`.
 * The request carries no cache-busting parameters, so conditional revalidation
 * (`If-None-Match` → `304`) can do its job on repeat opens. `cache: 'reload'` is
 * only passed as a recovery path when a `304` arrives without a cached body.
 */
export function getScanReportHtml(scanId: string, cache?: RequestCache): Promise<Response> {
  return apiRequestRaw(`${SCANS}/${encodeURIComponent(scanId)}/report/html`, {
    authenticated: true,
    cache,
  });
}

/** `GET /scans/{id}/report/pdf` — `application/pdf` with `ETag`. */
export function getScanReportPdf(scanId: string, cache?: RequestCache): Promise<Response> {
  return apiRequestRaw(`${SCANS}/${encodeURIComponent(scanId)}/report/pdf`, {
    authenticated: true,
    cache,
  });
}

/** `POST /scans/upload` — multipart `.json`/`.zip`, synchronous analysis. */
export function uploadScan(file: File): Promise<ScanUploadResponse> {
  const formData = new FormData();
  formData.append('file', file);
  return apiRequest<ScanUploadResponse>(`${SCANS}/upload`, {
    method: 'POST',
    formData,
  });
}

/** `DELETE /scans/{id}` → `204`. */
export function deleteScan(scanId: string): Promise<void> {
  return apiRequest<void>(`${SCANS}/${encodeURIComponent(scanId)}`, { method: 'DELETE' });
}

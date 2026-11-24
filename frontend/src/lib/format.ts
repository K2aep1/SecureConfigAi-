/**
 * Presentation helpers. Pure functions only — no React, no fetch.
 */

import type { ControlStatus, JsonValue, ScanStatus } from '../types';

/** Formats an ISO-8601 timestamp for a dense table. */
export function formatDateTime(value: string | null | undefined): string {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '—';
  return date.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  });
}

/** Short form for footers and list rows. */
export function formatDate(value: string | null | undefined): string {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '—';
  return date.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: '2-digit' });
}

/** "just now" / "4 min ago" — used for heartbeats and last-scan columns. */
export function formatRelative(value: string | null | undefined, now: number = Date.now()): string {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '—';
  const deltaMs = now - date.getTime();
  const future = deltaMs < 0;
  const seconds = Math.abs(Math.round(deltaMs / 1000));
  if (seconds < 45) return future ? 'in a moment' : 'just now';
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return future ? `in ${minutes} min` : `${minutes} min ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return future ? `in ${hours} h` : `${hours} h ago`;
  const days = Math.round(hours / 24);
  return future ? `in ${days} d` : `${days} d ago`;
}

/** `duration_ms` → "1 m 42 s". */
export function formatDurationMs(ms: number | null | undefined): string {
  if (ms === null || ms === undefined || !Number.isFinite(ms)) return '—';
  if (ms < 1000) return `${Math.max(0, Math.round(ms))} ms`;
  const totalSeconds = Math.round(ms / 1000);
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;
  if (hours > 0) return `${hours} h ${minutes} m`;
  if (minutes > 0) return `${minutes} m ${seconds} s`;
  return `${seconds} s`;
}

/** Elapsed wall-clock time for a running scan (mm:ss). */
export function formatElapsed(ms: number): string {
  const totalSeconds = Math.max(0, Math.floor(ms / 1000));
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  return `${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`;
}

export function formatBytes(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined || !Number.isFinite(bytes)) return '—';
  if (bytes < 1024) return `${bytes} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let value = bytes / 1024;
  let unitIndex = 0;
  while (value >= 1024 && unitIndex < units.length - 1) {
    value /= 1024;
    unitIndex += 1;
  }
  return `${value.toFixed(value >= 10 ? 0 : 1)} ${units[unitIndex]}`;
}

/** `null` is rendered as an explicit "not assessed", never as `0`. */
export function formatScore(score: number | null | undefined): string {
  return score === null || score === undefined || !Number.isFinite(score) ? '—' : String(score);
}

export function formatPercent(value: number | null | undefined): string {
  return value === null || value === undefined || !Number.isFinite(value) ? '—' : `${value}%`;
}

export function clampPercent(value: number | null | undefined): number {
  if (value === null || value === undefined || !Number.isFinite(value)) return 0;
  return Math.max(0, Math.min(100, value));
}

/** `not_applicable` → "Not applicable". */
export function humanize(value: string | null | undefined): string {
  if (!value) return '—';
  return value
    .replace(/[_-]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .replace(/^\w/, (character) => character.toUpperCase());
}

export function truncate(value: string, max = 90): string {
  if (value.length <= max) return value;
  return `${value.slice(0, max - 1)}…`;
}

/** Deterministic, readable rendering of an arbitrary JSON value. */
export function formatJsonValue(value: JsonValue | undefined): string {
  if (value === undefined) return '—';
  if (value === null) return 'null';
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return '[unserialisable value]';
  }
}

/** Compact single-line variant for table cells. */
export function formatJsonInline(value: JsonValue | undefined, max = 80): string {
  if (value === undefined) return '—';
  if (value === null) return 'null';
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  try {
    return truncate(JSON.stringify(value), max);
  } catch {
    return '[unserialisable value]';
  }
}

/** ISO-8601 value for a `<input type="datetime-local">` round-trip. */
export function toIsoOrUndefined(localDateTime: string): string | undefined {
  if (!localDateTime) return undefined;
  const date = new Date(localDateTime);
  if (Number.isNaN(date.getTime())) return undefined;
  return date.toISOString();
}

/** Stable list of the frozen control-state vocabulary, for filters. */
export const CONTROL_STATUSES: ControlStatus[] = [
  'compliant',
  'non_compliant',
  'not_applicable',
  'unknown',
  'error',
];

/** Stable list of the frozen scan-status vocabulary, for filters. */
export const SCAN_STATUSES: ScanStatus[] = [
  'queued',
  'running',
  'completed',
  'failed',
  'cancelled',
];

export function isTerminalScanStatus(status: ScanStatus | string | null | undefined): boolean {
  return status === 'completed' || status === 'failed' || status === 'cancelled';
}

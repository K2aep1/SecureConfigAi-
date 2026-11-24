/**
 * Central React Query key registry.
 *
 * Keys are hierarchical so a single invalidation can refresh a whole domain
 * (for example `queryKeys.scans.all` after a scan reaches a terminal status).
 */

import type { AuditLogFilters, PolicyListParams, ScanListFilters } from '../types';

export const queryKeys = {
  meta: {
    all: ['meta'] as const,
    app: () => ['meta', 'app'] as const,
    health: () => ['meta', 'health'] as const,
  },
  auth: {
    policy: () => ['auth', 'policy'] as const,
    me: () => ['auth', 'me'] as const,
  },
  scans: {
    all: ['scans'] as const,
    /**
     * `scope` is a client-side discriminator only: two screens can request the
     * same filters with different intents (a recent-scan strip versus the full
     * history) without sharing a cache entry. It is never sent to the API.
     */
    list: (filters: ScanListFilters & { scope?: string }) =>
      ['scans', 'list', filters] as const,
    detail: (scanId: string) => ['scans', 'detail', scanId] as const,
    status: (scanId: string) => ['scans', 'status', scanId] as const,
    results: (scanId: string) => ['scans', 'results', scanId] as const,
    document: (scanId: string) => ['scans', 'document', scanId] as const,
  },
  devices: {
    all: ['devices'] as const,
    list: () => ['devices', 'list'] as const,
    compare: () => ['devices', 'compare'] as const,
    exemptions: (deviceId: string) => ['devices', deviceId, 'exemptions'] as const,
  },
  policies: {
    all: ['policies'] as const,
    list: (params: PolicyListParams) => ['policies', 'list', params] as const,
    effective: () => ['policies', 'effective'] as const,
    baseline: () => ['policies', 'baseline'] as const,
  },
  admin: {
    users: () => ['admin', 'users'] as const,
    auditLogs: (filters: AuditLogFilters) => ['admin', 'audit-logs', filters] as const,
    stats: () => ['admin', 'stats'] as const,
    securityPolicy: () => ['admin', 'security-policy'] as const,
  },
  ai: {
    status: () => ['ai', 'status'] as const,
    sessions: () => ['ai', 'sessions'] as const,
    messages: (sessionId: string) => ['ai', 'chat', sessionId] as const,
    explain: (findingId: string) => ['ai', 'explain', findingId] as const,
    scanRecommendations: (scanId: string) => ['ai', 'recommendations', scanId] as const,
    riskPriorities: (scanId: string) => ['ai', 'risk-priorities', scanId] as const,
  },
};

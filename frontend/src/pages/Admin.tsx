/**
 * Administration.
 *
 * Three panels, each backed by exactly one documented route family:
 *  - Users   → `GET /admin/users`, `PATCH …/role`, `PATCH …/status`, `POST …/unlock`
 *  - Audit   → `GET /admin/audit-logs` (+ documented filters), `GET /admin/audit-logs/verify`
 *  - Storage → `GET /admin/stats`
 *
 * Self-demotion and self-disable are refused by the API with `400`; the UI
 * prevents the attempt outright for the signed-in account and explains why.
 */

import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  getAdminStats,
  listAuditLogs,
  listUsers,
  queryKeys,
  revokeUserSessions,
  unlockUser,
  updateUserRole,
  updateUserStatus,
  verifyAuditChain,
} from '../api';
import { DEFAULT_PAGE_SIZE, useCursorList } from '../hooks/useCursorList';
import { useDocumentTitle } from '../hooks/useAppData';
import { DataTable, LoadMore, type Column } from '../components/DataTable';
import { EnabledBadge, NeutralBadge, OutcomeBadge } from '../components/Badges';
import { MetricCard, MetricGrid } from '../components/MetricCard';
import { EmptyState, ErrorState, Notice } from '../components/States';
import { useConfirm } from '../components/ConfirmDialog';
import { useToast } from '../components/Toast';
import { useSession } from '../auth/SessionProvider';
import { errorToastMessage } from '../lib/errors';
import { formatBytes, formatDateTime, formatJsonValue, formatRelative, toIsoOrUndefined } from '../lib/format';
import type { AdminUser, AuditLogEntry, AuditLogFilters, UserRole } from '../types';

type Tab = 'users' | 'audit' | 'storage';

const TABS: Array<{ id: Tab; label: string }> = [
  { id: 'users', label: 'Users' },
  { id: 'audit', label: 'Audit log' },
  { id: 'storage', label: 'Storage' },
];

export default function AdminPage() {
  useDocumentTitle('Administration · SecureConfigAI');
  const [tab, setTab] = useState<Tab>('users');

  return (
    <div className="page">
      <div className="page-intro">
        <div>
          <span className="eyebrow">Governance</span>
          <h2>Administration</h2>
          <p>
            Account lifecycle and the tamper-evident audit trail. Every mutation here is itself
            audited by the backend.
          </p>
        </div>
        <div className="inline-actions">
          <Link className="button button-light" to="/admin/security-policy">
            Security policy
          </Link>
        </div>
      </div>

      <div className="tabs" role="tablist" aria-label="Administration sections">
        {TABS.map((entry) => (
          <button
            key={entry.id}
            type="button"
            role="tab"
            id={`admin-tab-${entry.id}`}
            aria-selected={tab === entry.id}
            aria-controls={`admin-panel-${entry.id}`}
            className={`tab${tab === entry.id ? ' tab-active' : ''}`}
            onClick={() => setTab(entry.id)}
          >
            {entry.label}
          </button>
        ))}
      </div>

      <div
        role="tabpanel"
        id={`admin-panel-${tab}`}
        aria-labelledby={`admin-tab-${tab}`}
        className="tab-panel"
      >
        {tab === 'users' ? <UsersPanel /> : null}
        {tab === 'audit' ? <AuditPanel /> : null}
        {tab === 'storage' ? <StoragePanel /> : null}
      </div>
    </div>
  );
}

function UsersPanel() {
  const toast = useToast();
  const confirm = useConfirm();
  const queryClient = useQueryClient();
  const { user: currentUser } = useSession();
  const [search, setSearch] = useState('');
  const [roleFilter, setRoleFilter] = useState<'all' | UserRole>('all');
  const [statusFilter, setStatusFilter] = useState<'all' | 'active' | 'disabled' | 'locked'>('all');

  const users = useCursorList<AdminUser>({
    queryKey: queryKeys.admin.users(),
    fetchPage: (cursor, signal) => listUsers({ limit: DEFAULT_PAGE_SIZE, cursor }, signal),
    staleTime: 15_000,
  });

  function invalidate() {
    void queryClient.invalidateQueries({ queryKey: queryKeys.admin.users() });
    void queryClient.invalidateQueries({ queryKey: queryKeys.admin.auditLogs({}) });
  }

  const roleChange = useMutation({
    mutationFn: ({ userId, role }: { userId: string; role: UserRole }) => updateUserRole(userId, role),
    onSuccess: () => {
      toast.push({ tone: 'success', title: 'Role updated' });
      invalidate();
    },
    onError: (error) => {
      toast.push({ tone: 'error', title: 'Could not change the role', message: errorToastMessage(error) });
    },
  });

  const statusChange = useMutation({
    mutationFn: ({ userId, isActive }: { userId: string; isActive: boolean }) =>
      updateUserStatus(userId, isActive),
    onSuccess: (_result, variables) => {
      toast.push({
        tone: 'success',
        title: variables.isActive ? 'Account enabled' : 'Account disabled',
        message: variables.isActive
          ? 'The user can sign in again.'
          : 'The account can no longer sign in; existing sessions are refused at the API.',
      });
      invalidate();
    },
    onError: (error) => {
      toast.push({ tone: 'error', title: 'Could not change the account state', message: errorToastMessage(error) });
    },
  });

  const unlock = useMutation({
    mutationFn: (userId: string) => unlockUser(userId),
    onSuccess: () => {
      toast.push({
        tone: 'success',
        title: 'Account unlocked',
        message: 'The lockout and failed-attempt counter were cleared.',
      });
      invalidate();
    },
    onError: (error) => {
      toast.push({ tone: 'error', title: 'Could not unlock the account', message: errorToastMessage(error) });
    },
  });

  const revokeSessions = useMutation({
    mutationFn: (userId: string) => revokeUserSessions(userId),
    onSuccess: (_result, userId) => {
      const target = users.items.find((item) => item.id === userId);
      toast.push({
        tone: 'success',
        title: 'Sessions revoked',
        message: target ? `Refresh sessions for ${target.email} were revoked. Existing access tokens expire normally.` : 'Refresh sessions were revoked.',
      });
      invalidate();
    },
    onError: (error) => {
      toast.push({ tone: 'error', title: 'Could not revoke sessions', message: errorToastMessage(error) });
    },
  });

  const columns: Column<AdminUser>[] = [
    {
      id: 'user',
      header: 'User',
      width: '24%',
      cell: (row) => (
        <span className="cell-stack">
          <span className="cell-title">
            {row.email}
            {row.id === currentUser?.id ? <span className="cell-self"> (you)</span> : null}
          </span>
          <span className="cell-subtle">{row.full_name ?? 'No name recorded'}</span>
        </span>
      ),
    },
    {
      id: 'role',
      header: 'Role',
      width: '14%',
      cell: (row) => {
        const isSelf = row.id === currentUser?.id;
        return (
          <select
            value={row.role}
            aria-label={`Role for ${row.email}`}
            disabled={isSelf || roleChange.isPending}
            title={isSelf ? 'You cannot change your own role — the API refuses self-demotion.' : undefined}
            onChange={(event) =>
              roleChange.mutate({ userId: row.id, role: event.target.value as UserRole })
            }
          >
            <option value="user">user</option>
            <option value="admin">admin</option>
          </select>
        );
      },
    },
    {
      id: 'status',
      header: 'Status',
      width: '13%',
      cell: (row) => (
        <span className="cell-stack">
          <EnabledBadge enabled={row.is_active} />
          {row.locked_until ? (
            <NeutralBadge
              label="locked"
              title={`Locked until ${formatDateTime(row.locked_until)}`}
            />
          ) : null}
        </span>
      ),
    },
    {
      id: 'logins',
      header: 'Failed logins',
      align: 'right',
      hideBelow: 'md',
      width: '11%',
      cell: (row) => (
        <span title={`Locked until ${formatDateTime(row.locked_until)}`}>
          {row.failed_login_count}
        </span>
      ),
    },
    {
      id: 'lastLogin',
      header: 'Last sign-in',
      hideBelow: 'lg',
      width: '14%',
      cell: (row) => (
        <span className="cell-stack">
          <span>{formatRelative(row.last_login_at)}</span>
          <span className="cell-subtle">{formatDateTime(row.last_login_at)}</span>
        </span>
      ),
    },
    {
      id: 'created',
      header: 'Created',
      hideBelow: 'lg',
      width: '12%',
      cell: (row) => formatDateTime(row.created_at),
    },
    {
      id: 'actions',
      header: 'Actions',
      align: 'right',
      width: '18%',
      cell: (row) => {
        const isSelf = row.id === currentUser?.id;
        return (
          <span className="inline-actions">
            <button
              type="button"
              className="text-button"
              disabled={isSelf || unlock.isPending || row.failed_login_count === 0}
              title={
                isSelf
                  ? 'Nothing to unlock on your own account.'
                  : row.failed_login_count === 0
                    ? 'No failed attempts recorded.'
                    : 'Clear the lockout and failed-attempt counter.'
              }
              onClick={() => unlock.mutate(row.id)}
            >
              Unlock
            </button>
            <button
              type="button"
              className="text-button"
              disabled={isSelf || revokeSessions.isPending}
              title={isSelf ? 'Use account security settings for your own sessions.' : 'Force this user to authenticate again on the next refresh.'}
              onClick={async () => {
                const confirmed = await confirm({
                  title: `Revoke sessions for ${row.email}?`,
                  message: 'All refresh sessions for this account will be revoked. Existing access tokens remain valid until they expire.',
                  confirmLabel: 'Revoke sessions',
                  destructive: true,
                });
                if (confirmed) revokeSessions.mutate(row.id);
              }}
            >
              Revoke sessions
            </button>
            <button
              type="button"
              className={row.is_active ? 'text-button danger-text' : 'text-button'}
              disabled={isSelf || statusChange.isPending}
              title={isSelf ? 'You cannot disable your own account — the API refuses it.' : undefined}
              onClick={async () => {
                if (row.is_active) {
                  const confirmed = await confirm({
                    title: `Disable ${row.email}?`,
                    message:
                      'The account is disabled. The user can no longer sign in, and the API refuses requests made with its tokens.',
                    confirmLabel: 'Disable account',
                    destructive: true,
                  });
                  if (!confirmed) return;
                }
                statusChange.mutate({ userId: row.id, isActive: !row.is_active });
              }}
            >
              {row.is_active ? 'Disable' : 'Enable'}
            </button>
          </span>
        );
      },
    },
  ];

  const filteredUsers = users.items.filter((row) => {
    const q = search.trim().toLowerCase();
    const matchesSearch = !q || row.email.toLowerCase().includes(q) || (row.full_name ?? '').toLowerCase().includes(q);
    const matchesRole = roleFilter === 'all' || row.role === roleFilter;
    const matchesStatus = statusFilter === 'all'
      || (statusFilter === 'active' && row.is_active && !row.locked_until)
      || (statusFilter === 'disabled' && !row.is_active)
      || (statusFilter === 'locked' && Boolean(row.locked_until));
    return matchesSearch && matchesRole && matchesStatus;
  });
  const activeCount = users.items.filter((u) => u.is_active).length;
  const adminCount = users.items.filter((u) => u.role === 'admin').length;
  const lockedCount = users.items.filter((u) => Boolean(u.locked_until)).length;

  return (
    <section className="panel">
      <MetricGrid>
        <MetricCard label="Users loaded" value={users.count} />
        <MetricCard label="Active accounts" value={activeCount} />
        <MetricCard label="Administrators" value={adminCount} />
        <MetricCard label="Locked accounts" value={lockedCount} />
      </MetricGrid>
      <div className="panel-head">
        <div>
          <h2>Users</h2>
          <p>
            {users.count} loaded. Self-demotion and self-disable are blocked by the API with a 400, so
            those controls are disabled for your own account.
          </p>
        </div>
        <button type="button" className="button button-light" onClick={users.reload}>
          Refresh
        </button>
      </div>

      <div className="user-management-filters">
        <input
          className="user-management-search"
          type="search"
          aria-label="Search users"
          placeholder="Search email or name…"
          value={search}
          onChange={(event) => setSearch(event.target.value)}
        />
        <select aria-label="Filter by role" value={roleFilter} onChange={(event) => setRoleFilter(event.target.value as 'all' | UserRole)}>
          <option value="all">All roles</option>
          <option value="admin">Administrators</option>
          <option value="user">Standard users</option>
        </select>
        <select aria-label="Filter by account status" value={statusFilter} onChange={(event) => setStatusFilter(event.target.value as 'all' | 'active' | 'disabled' | 'locked')}>
          <option value="all">All statuses</option>
          <option value="active">Active</option>
          <option value="disabled">Disabled</option>
          <option value="locked">Locked</option>
        </select>
      </div>
      {users.isError ? (
        <ErrorState error={users.error} onRetry={users.reload} scope="Users" />
      ) : (
        <>
          <DataTable
            columns={columns}
            rows={filteredUsers}
            rowKey={(row) => row.id}
            caption="Platform users"
            busy={users.isLoading}
            busyLabel="Loading users…"
            empty={<EmptyState title={users.items.length ? 'No users match these filters' : 'No users returned'} compact />}
          />
          <LoadMore
            hasMore={users.hasMore}
            isLoading={users.isLoadingMore}
            onLoadMore={users.loadMore}
            loadedCount={users.count}
            pageSize={DEFAULT_PAGE_SIZE}
            unit="users"
          />
        </>
      )}
    </section>
  );
}

function AuditPanel() {
  const toast = useToast();
  const [draft, setDraft] = useState({
    action: '',
    actor_id: '',
    outcome: '',
    from: '',
    to: '',
  });
  const [applied, setApplied] = useState<AuditLogFilters>({});

  const filters: AuditLogFilters = useMemo(
    () => ({ limit: DEFAULT_PAGE_SIZE, ...applied }),
    [applied],
  );

  const logs = useCursorList<AuditLogEntry>({
    queryKey: queryKeys.admin.auditLogs(filters),
    fetchPage: (cursor, signal) => listAuditLogs({ ...filters, cursor }, signal),
    staleTime: 10_000,
  });

  const verify = useMutation({
    mutationFn: () => verifyAuditChain(),
    onError: (error) => {
      toast.push({
        tone: 'error',
        title: 'Chain verification failed to run',
        message: errorToastMessage(error),
      });
    },
  });

  const columns: Column<AuditLogEntry>[] = [
    {
      id: 'created',
      header: 'When',
      width: '15%',
      cell: (row) => (
        <span className="cell-stack">
          <span>{formatDateTime(row.created_at)}</span>
          <span className="cell-subtle">{formatRelative(row.created_at)}</span>
        </span>
      ),
    },
    {
      id: 'action',
      header: 'Action',
      width: '18%',
      cell: (row) => <code className="cell-code">{row.action}</code>,
    },
    {
      id: 'actor',
      header: 'Actor',
      width: '17%',
      cell: (row) => (
        <span className="cell-stack">
          <span>{row.actor_email ?? 'system'}</span>
          <code className="cell-code cell-subtle">{row.actor_id ?? '—'}</code>
        </span>
      ),
    },
    {
      id: 'entity',
      header: 'Entity',
      hideBelow: 'lg',
      width: '13%',
      cell: (row) => (
        <span className="cell-stack">
          <span>{row.entity_type ?? '—'}</span>
          <span className="cell-subtle mono">{row.entity_id ?? ''}</span>
        </span>
      ),
    },
    {
      id: 'outcome',
      header: 'Outcome',
      width: '10%',
      cell: (row) => <OutcomeBadge outcome={row.outcome} />,
    },
    {
      id: 'source',
      header: 'Source',
      hideBelow: 'lg',
      width: '11%',
      cell: (row) => (
        <span className="cell-stack">
          <span className="mono">{row.ip_address ?? '—'}</span>
          <span className="cell-subtle mono">{row.request_id?.slice(0, 12) ?? ''}</span>
        </span>
      ),
    },
    {
      id: 'hashes',
      header: 'Chain',
      hideBelow: 'lg',
      width: '12%',
      cell: (row) => (
        <span className="cell-stack mono cell-subtle" title={`entry ${row.entry_hash ?? '—'}\nprev ${row.prev_hash ?? '—'}`}>
          <span>{row.entry_hash ? `${row.entry_hash.slice(0, 10)}…` : '—'}</span>
          <span>{row.prev_hash ? `prev ${row.prev_hash.slice(0, 8)}…` : 'genesis'}</span>
        </span>
      ),
    },
    {
      id: 'details',
      header: 'Details',
      width: '14%',
      cell: (row) =>
        row.details && Object.keys(row.details).length > 0 ? (
          <details className="inline-disclosure">
            <summary>View</summary>
            <pre className="json-block">{formatJsonValue(row.details)}</pre>
          </details>
        ) : (
          <span className="muted">—</span>
        ),
    },
  ];

  function applyFilters() {
    setApplied({
      action: draft.action.trim() || undefined,
      actor_id: draft.actor_id.trim() || undefined,
      outcome: draft.outcome.trim() || undefined,
      from: toIsoOrUndefined(draft.from),
      to: toIsoOrUndefined(draft.to),
    });
  }

  return (
    <section className="panel">
      <div className="panel-head">
        <div>
          <h2>Audit log</h2>
          <p>
            Hash-chained entries. Filters map onto the documented parameters `action`, `actor_id`,
            `outcome`, `from` and `to`.
          </p>
        </div>
        <div className="inline-actions">
          <button type="button" className="button button-light" onClick={logs.reload}>
            Refresh
          </button>
          <button
            type="button"
            className="button button-primary"
            onClick={() => verify.mutate()}
            disabled={verify.isPending}
          >
            {verify.isPending ? 'Verifying…' : 'Verify chain'}
          </button>
        </div>
      </div>

      {verify.data ? (
        <Notice
          tone={verify.data.chain_valid ? 'success' : 'error'}
          title={verify.data.chain_valid ? 'Audit chain intact' : 'Audit chain broken'}
        >
          {verify.data.chain_valid ? (
            <>
              All {verify.data.checked} entries verified: each entry hash links to its predecessor.
            </>
          ) : (
            <>
              The chain breaks at entry <code>{verify.data.first_broken_id ?? 'unknown'}</code> after{' '}
              {verify.data.checked} verified entries. Treat the trail beyond that point as unreliable
              and investigate before drawing conclusions from it.
            </>
          )}
        </Notice>
      ) : null}

      <div className="filter-grid">
        <label className="field">
          <span className="field-label">Action</span>
          <input
            type="text"
            value={draft.action}
            onChange={(event) => setDraft({ ...draft, action: event.target.value })}
            placeholder="e.g. auth.login"
          />
        </label>
        <label className="field">
          <span className="field-label">Actor ID</span>
          <input
            type="text"
            value={draft.actor_id}
            onChange={(event) => setDraft({ ...draft, actor_id: event.target.value })}
            placeholder="User UUID"
            spellCheck={false}
          />
        </label>
        <label className="field">
          <span className="field-label">Outcome</span>
          <select
            value={draft.outcome}
            onChange={(event) => setDraft({ ...draft, outcome: event.target.value })}
          >
            <option value="">Any outcome</option>
            <option value="success">success</option>
            <option value="failure">failure</option>
            <option value="denied">denied</option>
          </select>
        </label>
        <label className="field">
          <span className="field-label">From</span>
          <input
            type="datetime-local"
            value={draft.from}
            onChange={(event) => setDraft({ ...draft, from: event.target.value })}
          />
        </label>
        <label className="field">
          <span className="field-label">To</span>
          <input
            type="datetime-local"
            value={draft.to}
            onChange={(event) => setDraft({ ...draft, to: event.target.value })}
          />
        </label>
        <div className="field">
          <span className="field-label">&nbsp;</span>
          <div className="inline-actions">
            <button type="button" className="button button-primary" onClick={applyFilters}>
              Apply filters
            </button>
            <button
              type="button"
              className="button button-light"
              onClick={() => {
                setDraft({ action: '', actor_id: '', outcome: '', from: '', to: '' });
                setApplied({});
              }}
            >
              Clear
            </button>
          </div>
        </div>
      </div>

      {logs.isError ? (
        <ErrorState error={logs.error} onRetry={logs.reload} scope="Audit log" />
      ) : (
        <>
          <DataTable
            columns={columns}
            rows={logs.items}
            rowKey={(row) => row.id}
            caption="Audit log entries"
            busy={logs.isLoading}
            busyLabel="Loading audit entries…"
            empty={
              <EmptyState
                title="No audit entries match"
                description="Widen the time range or clear the filters."
              />
            }
          />
          <LoadMore
            hasMore={logs.hasMore}
            isLoading={logs.isLoadingMore}
            onLoadMore={logs.loadMore}
            loadedCount={logs.count}
            pageSize={DEFAULT_PAGE_SIZE}
            unit="entries"
          />
        </>
      )}
    </section>
  );
}

function StoragePanel() {
  const stats = useQuery({
    queryKey: queryKeys.admin.stats(),
    staleTime: 60_000,
    queryFn: ({ signal }) => getAdminStats(signal),
  });

  return (
    <section className="panel">
      <div className="panel-head">
        <div>
          <h2>Storage and record counts</h2>
          <p>Reported by `GET /admin/stats`.</p>
        </div>
        <button type="button" className="button button-light" onClick={() => void stats.refetch()}>
          Refresh
        </button>
      </div>

      {stats.isError ? (
        <ErrorState error={stats.error} onRetry={() => void stats.refetch()} scope="Statistics" />
      ) : null}

      {stats.data ? (
        <MetricGrid columns={4}>
          <MetricCard label="Users" value={stats.data.users} />
          <MetricCard label="Devices" value={stats.data.devices} />
          <MetricCard label="Scans" value={stats.data.scans} />
          <MetricCard label="Findings" value={stats.data.findings} />
          <MetricCard label="Audit entries" value={stats.data.audit_entries} />
          <MetricCard
            label="Generated reports"
            value={stats.data.reports ?? '—'}
            note="Artefacts currently stored on disk"
          />
          <MetricCard label="Database size" value={formatBytes(stats.data.database_bytes)} />
          <MetricCard label="Evidence size" value={formatBytes(stats.data.evidence_bytes)} />
        </MetricGrid>
      ) : null}
    </section>
  );
}

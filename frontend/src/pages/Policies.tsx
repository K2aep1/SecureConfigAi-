/**
 * Policies — baseline overrides.
 *
 * Behaviours that matter here:
 *  - `include_disabled` is a documented query parameter, so the toggle maps onto
 *    it directly rather than filtering client-side.
 *  - Enable/disable works in **both** directions through `PATCH /policies/{id}/toggle`
 *    (the endpoint flips state and returns the new row), and the UI always shows
 *    the state the server reported back.
 *  - Each override is shown next to the value it resolves over, from
 *    `GET /policies/effective` (admin-only, so it is only requested for admins).
 */

import { useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  createPolicy,
  deletePolicy,
  getEffectivePolicies,
  listPolicies,
  queryKeys,
  togglePolicy,
} from '../api';
import { DEFAULT_PAGE_SIZE, useCursorList } from '../hooks/useCursorList';
import { useDebouncedValue, useDocumentTitle } from '../hooks/useAppData';
import { DataTable, LoadMore, type Column } from '../components/DataTable';
import { EnabledBadge, PolicyLayerBadge, SeverityBadge, NeutralBadge } from '../components/Badges';
import { Drawer } from '../components/Drawer';
import { EmptyState, ErrorState, Notice } from '../components/States';
import { useConfirm } from '../components/ConfirmDialog';
import { useToast } from '../components/Toast';
import { useSession } from '../auth/SessionProvider';
import { errorToastMessage } from '../lib/errors';
import { formatJsonInline, humanize } from '../lib/format';
import { tryParseJsonValue } from '../lib/json';
import type { EffectiveControl, Policy } from '../types';

/**
 * `/policies/effective` reports the winning layer per field in `sources`
 * (`baseline` | `override` | `device`). The most specific non-baseline layer is
 * the interesting one for an override row, so that is what the badge shows.
 */
function dominantLayer(sources: Record<string, string> | undefined): string | null {
  if (!sources) return null;
  const layers = Object.values(sources);
  if (layers.includes('override')) return 'override';
  if (layers.includes('device')) return 'device';
  return layers[0] ?? 'baseline';
}

function policyTarget(policy: Policy): string {
  return policy.control_id;
}

function ResolvedComparison({ control }: { control: EffectiveControl | undefined }) {
  if (!control) {
    return <span className="muted">Not present in the resolved control set</span>;
  }
  const weightOverridden = control.weight !== control.baseline_weight;
  const severityOverridden = control.severity !== control.baseline_severity;

  return (
    <span className="cell-stack resolved">
      <span className="resolved-row">
        <span className="resolved-label">weight</span>
        <span className="resolved-baseline">{control.baseline_weight}</span>
        <span aria-hidden="true">→</span>
        <strong>{control.weight}</strong>
        {weightOverridden ? <PolicyLayerBadge layer={control.sources?.weight ?? null} /> : null}
      </span>
      <span className="resolved-row">
        <span className="resolved-label">severity</span>
        <span className="resolved-baseline">{humanize(control.baseline_severity)}</span>
        <span aria-hidden="true">→</span>
        <strong>{humanize(control.severity)}</strong>
        {severityOverridden ? (
          <PolicyLayerBadge layer={control.sources?.severity ?? null} />
        ) : null}
      </span>
    </span>
  );
}

export default function PoliciesPage() {
  useDocumentTitle('Policies · SecureConfigAI');
  const { isAdmin } = useSession();
  const toast = useToast();
  const confirm = useConfirm();
  const queryClient = useQueryClient();

  const [includeDisabled, setIncludeDisabled] = useState(true);
  const [search, setSearch] = useState('');
  const debouncedSearch = useDebouncedValue(search, 300);
  const [showCreate, setShowCreate] = useState(false);

  const params = { limit: DEFAULT_PAGE_SIZE, include_disabled: includeDisabled };

  const policies = useCursorList<Policy>({
    queryKey: queryKeys.policies.list(params),
    fetchPage: (cursor, signal) => listPolicies({ ...params, cursor }, signal),
    staleTime: 10_000,
  });

  const effective = useQuery({
    queryKey: queryKeys.policies.effective(),
    enabled: isAdmin,
    staleTime: 30_000,
    queryFn: ({ signal }) => getEffectivePolicies(signal),
  });

  const effectiveByControl = useMemo(() => {
    const map = new Map<string, EffectiveControl>();
    for (const control of effective.data?.controls ?? []) {
      if (control.control_id) map.set(control.control_id, control);
    }
    return map;
  }, [effective.data]);

  const toggle = useMutation({
    mutationFn: (policyId: string) => togglePolicy(policyId),
    onSuccess: (updated) => {
      toast.push({
        tone: 'success',
        title: `${updated.name} ${updated.is_enabled ? 'enabled' : 'disabled'}`,
        message: updated.is_enabled
          ? 'The override now participates in policy resolution.'
          : 'The override is skipped during resolution; the baseline value applies again.',
      });
      void queryClient.invalidateQueries({ queryKey: queryKeys.policies.all });
      if (isAdmin) void queryClient.invalidateQueries({ queryKey: queryKeys.policies.effective() });
    },
    onError: (error) => {
      toast.push({
        tone: 'error',
        title: 'Could not change the override state',
        message: errorToastMessage(error),
      });
    },
  });

  const remove = useMutation({
    mutationFn: (policyId: string) => deletePolicy(policyId),
    onSuccess: () => {
      toast.push({ tone: 'success', title: 'Override deleted' });
      void queryClient.invalidateQueries({ queryKey: queryKeys.policies.all });
      if (isAdmin) void queryClient.invalidateQueries({ queryKey: queryKeys.policies.effective() });
    },
    onError: (error) => {
      toast.push({
        tone: 'error',
        title: 'Could not delete the override',
        message: errorToastMessage(error),
      });
    },
  });

  async function onDelete(policy: Policy) {
    const confirmed = await confirm({
      title: `Delete "${policy.name}"?`,
      message: (
        <>
          The override is removed permanently. Historical findings are detached rather than deleted,
          so past evidence survives.
        </>
      ),
      confirmLabel: 'Delete override',
      destructive: true,
    });
    if (confirmed) remove.mutate(policy.id);
  }

  const rows = useMemo(() => {
    const needle = debouncedSearch.trim().toLowerCase();
    if (!needle) return policies.items;
    return policies.items.filter((policy) =>
      `${policy.name} ${policyTarget(policy)} ${policy.category ?? ''} ${policy.description ?? ''}`
        .toLowerCase()
        .includes(needle),
    );
  }, [policies.items, debouncedSearch]);

  const columns: Column<Policy>[] = [
    {
      id: 'name',
      header: 'Override',
      width: '24%',
      cell: (row) => (
        <span className="cell-stack">
          <span className="cell-title">{row.name}</span>
          {row.description ? <span className="cell-subtle">{row.description}</span> : null}
        </span>
      ),
    },
    {
      id: 'target',
      header: 'Target control',
      width: '14%',
      cell: (row) => <code className="cell-code">{policyTarget(row)}</code>,
    },
    {
      id: 'category',
      header: 'Category',
      hideBelow: 'lg',
      width: '12%',
      cell: (row) => row.category ?? <span className="muted">—</span>,
    },
    {
      id: 'severity',
      header: 'Severity',
      width: '10%',
      cell: (row) =>
        row.severity ? <SeverityBadge severity={row.severity} /> : <span className="muted">—</span>,
    },
    {
      id: 'weight',
      header: 'Weight',
      align: 'right',
      hideBelow: 'lg',
      width: '7%',
      cell: (row) => (row.weight === null || row.weight === undefined ? '—' : row.weight),
    },
    {
      id: 'overrideValue',
      header: 'Override value',
      hideBelow: 'lg',
      width: '15%',
      cell: (row) => (
        <code className="cell-code" title={formatJsonInline(row.expected_value, 500)}>
          {formatJsonInline(row.expected_value, 42)}
        </code>
      ),
    },
    {
      id: 'resolved',
      header: 'Baseline → resolved',
      width: '22%',
      cell: (row) => {
        if (!isAdmin) return <span className="muted">admin only</span>;
        return <ResolvedComparison control={effectiveByControl.get(policyTarget(row))} />;
      },
    },
    {
      id: 'state',
      header: 'State',
      width: '11%',
      cell: (row) => <EnabledBadge enabled={row.is_enabled} />,
    },
    {
      id: 'actions',
      header: 'Actions',
      align: 'right',
      width: '14%',
      cell: (row) =>
        isAdmin ? (
          <span className="inline-actions">
            <button
              type="button"
              className="text-button"
              onClick={() => toggle.mutate(row.id)}
              disabled={toggle.isPending}
            >
              {row.is_enabled ? 'Disable' : 'Enable'}
            </button>
            <button
              type="button"
              className="text-button danger-text"
              onClick={() => void onDelete(row)}
              disabled={remove.isPending}
            >
              Delete
            </button>
          </span>
        ) : (
          <span className="muted">read-only</span>
        ),
    },
  ];

  return (
    <div className="page">
      <div className="page-intro">
        <div>
          <span className="eyebrow">Policy management</span>
          <h2>Policies</h2>
          <p>
            Overrides layer over the shipped baseline. Resolution order is baseline → override →
            device, and the resolved value is shown next to each override.
          </p>
        </div>
        <div className="inline-actions">
          <button type="button" className="button button-light" onClick={policies.reload}>
            Refresh
          </button>
          {isAdmin ? (
            <button
              type="button"
              className="button button-primary"
              onClick={() => setShowCreate(true)}
            >
              New override
            </button>
          ) : null}
        </div>
      </div>

      {!isAdmin ? (
        <Notice tone="info" title="Read-only view">
          Creating, enabling, disabling and deleting overrides are administrator actions, and
          `GET /policies/effective` is admin-only — so resolved baseline values are not shown. The API
          will also refuse these writes with a 403.
        </Notice>
      ) : null}

      <section className="panel">
        <div className="panel-head">
          <div>
            <h2>Overrides</h2>
            <p>
              {policies.count} loaded{includeDisabled ? '' : ' · disabled overrides hidden'}
            </p>
          </div>
          <div className="table-tools">
            <label className="toggle">
              <input
                type="checkbox"
                checked={includeDisabled}
                onChange={(event) => setIncludeDisabled(event.target.checked)}
              />
              <span>Include disabled</span>
            </label>
            <label className="field field-inline">
              <span className="visually-hidden">Search overrides</span>
              <input
                type="search"
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                placeholder="Search overrides"
              />
            </label>
          </div>
        </div>

        {policies.isError ? (
          <ErrorState error={policies.error} onRetry={policies.reload} scope="Policy overrides" />
        ) : (
          <>
            <DataTable
              columns={columns}
              rows={rows}
              rowKey={(row) => row.id}
              caption="Policy overrides layered over the baseline"
              busy={policies.isLoading}
              busyLabel="Loading overrides…"
              empty={
                <EmptyState
                  title={
                    policies.items.length === 0
                      ? 'No overrides defined'
                      : 'No overrides match this search'
                  }
                  description={
                    policies.items.length === 0
                      ? 'The baseline applies unchanged. Create an override to deviate for specific controls.'
                      : 'Clear the search box to see every loaded override.'
                  }
                  action={
                    isAdmin && policies.items.length === 0 ? (
                      <button
                        type="button"
                        className="button button-primary"
                        onClick={() => setShowCreate(true)}
                      >
                        Create the first override
                      </button>
                    ) : null
                  }
                />
              }
            />
            <LoadMore
              hasMore={policies.hasMore}
              isLoading={policies.isLoadingMore}
              onLoadMore={policies.loadMore}
              loadedCount={policies.count}
              pageSize={DEFAULT_PAGE_SIZE}
              unit="overrides"
            />
          </>
        )}

        {isAdmin && effective.isError ? (
          <ErrorState
            error={effective.error}
            onRetry={() => void effective.refetch()}
            scope="Resolved control set"
            compact
          />
        ) : null}
      </section>

      {isAdmin ? (
        <section className="panel">
          <div className="panel-head">
            <div>
              <h2>Resolved control set</h2>
              <p>
                {effective.data
                  ? `${effective.data.controls.length} controls resolved from baseline ${effective.data.baseline_id} v${effective.data.baseline_version} · total weight ${effective.data.total_weight}.`
                  : 'Loading the resolved control set…'}
              </p>
            </div>
          </div>
          {effective.data && effective.data.controls.length === 0 ? (
            <EmptyState
              title="Nothing resolved"
              description="The API returned an empty resolved control set."
              compact
            />
          ) : null}
          {effective.data && effective.data.controls.length > 0 ? (
            <DataTable
              columns={[
                {
                  id: 'control',
                  header: 'Control',
                  width: '15%',
                  cell: (row) => <code className="cell-code">{row.control_id}</code>,
                },
                {
                  id: 'title',
                  header: 'Title',
                  cell: (row) => row.title,
                },
                {
                  id: 'layer',
                  header: 'Resolved by',
                  width: '13%',
                  cell: (row) => <PolicyLayerBadge layer={dominantLayer(row.sources)} />,
                },
                {
                  id: 'weight',
                  header: 'Weight (baseline → resolved)',
                  width: '19%',
                  cell: (row) => (
                    <span className="resolved-row">
                      <span className="resolved-baseline">{row.baseline_weight}</span>
                      <span aria-hidden="true">→</span>
                      <strong>{row.weight}</strong>
                      {row.weight !== row.baseline_weight ? (
                        <PolicyLayerBadge layer={row.sources?.weight ?? null} />
                      ) : null}
                    </span>
                  ),
                },
                {
                  id: 'severity',
                  header: 'Severity (baseline → resolved)',
                  width: '17%',
                  cell: (row) => (
                    <span className="resolved-row">
                      <span className="resolved-baseline">{humanize(row.baseline_severity)}</span>
                      <span aria-hidden="true">→</span>
                      <SeverityBadge severity={row.severity} />
                    </span>
                  ),
                },
                {
                  id: 'enabled',
                  header: 'Override',
                  width: '10%',
                  cell: (row) => <EnabledBadge enabled={row.enabled} />,
                },
                {
                  id: 'exempt',
                  header: 'Exempt',
                  width: '10%',
                  cell: (row) =>
                    row.exempted ? (
                      <NeutralBadge label="Exempt" title={row.exemption_reason ?? 'An exemption applies on this device.'} />
                    ) : (
                      <span className="muted">—</span>
                    ),
                },
                {
                  id: 'category',
                  header: 'Category',
                  hideBelow: 'lg',
                  cell: (row) => row.category,
                },
              ]}
              rows={effective.data.controls}
              rowKey={(row) => row.control_id}
              caption="Resolved control set"
              empty={<EmptyState title="Nothing resolved" compact />}
            />
          ) : null}
        </section>
      ) : null}

      <CreatePolicyDrawer open={showCreate} onClose={() => setShowCreate(false)} />
    </div>
  );
}

function CreatePolicyDrawer({ open, onClose }: { open: boolean; onClose: () => void }) {
  const toast = useToast();
  const queryClient = useQueryClient();
  const [form, setForm] = useState({
    name: '',
    controlId: '',
    category: '',
    severity: 'medium',
    weight: '1',
    description: '',
    expectedValue: '{\n  "operator": "==",\n  "value": true\n}',
    recommendation: '',
    isEnabled: true,
  });
  const [jsonError, setJsonError] = useState<string | null>(null);

  const create = useMutation({
    mutationFn: () => {
      const parsedExpected = tryParseJsonValue(form.expectedValue);
      if (!parsedExpected.ok) {
        throw new Error(`Expected value: ${parsedExpected.error}`);
      }
      return createPolicy({
        control_id: form.controlId.trim(),
        name: form.name.trim(),
        description: form.description.trim() || undefined,
        category: form.category.trim() || undefined,
        severity: form.severity,
        weight: Number(form.weight) || undefined,
        expected_value: parsedExpected.value,
        recommendation_template: form.recommendation.trim() || undefined,
        is_enabled: form.isEnabled,
      });
    },
    onSuccess: (policy) => {
      toast.push({
        tone: 'success',
        title: `Override "${policy.name}" created`,
        message: 'It applies from the next assessment onward.',
      });
      void queryClient.invalidateQueries({ queryKey: queryKeys.policies.all });
      void queryClient.invalidateQueries({ queryKey: queryKeys.policies.effective() });
      onClose();
    },
    onError: (error) => {
      setJsonError(error instanceof Error ? error.message : null);
      toast.push({
        tone: 'error',
        title: 'Could not create the override',
        message: errorToastMessage(error),
      });
    },
  });

  function update<K extends keyof typeof form>(key: K, value: (typeof form)[K]) {
    setForm((current) => ({ ...current, [key]: value }));
  }

  return (
    <Drawer
      open={open}
      onClose={onClose}
      width="wide"
      title="New policy override"
      subtitle="Overrides are keyed by control ID. A disabled override is stored but skipped during resolution."
      footer={
        <div className="inline-actions inline-actions-end">
          <button type="button" className="button button-light" onClick={onClose}>
            Cancel
          </button>
          <button
            type="button"
            className="button button-primary"
            onClick={() => create.mutate()}
            disabled={create.isPending || form.name.trim() === '' || form.controlId.trim() === ''}
          >
            {create.isPending ? 'Creating…' : 'Create override'}
          </button>
        </div>
      }
    >
      <div className="form-grid">
        <label className="field">
          <span className="field-label">Name</span>
          <input
            type="text"
            value={form.name}
            onChange={(event) => update('name', event.target.value)}
            placeholder="Stricter SMB signing requirement"
            required
          />
        </label>
        <label className="field">
          <span className="field-label">Control ID</span>
          <input
            type="text"
            value={form.controlId}
            onChange={(event) => update('controlId', event.target.value)}
            placeholder="WIN-SMB-002"
            required
          />
        </label>
        <label className="field">
          <span className="field-label">Category</span>
          <input
            type="text"
            value={form.category}
            onChange={(event) => update('category', event.target.value)}
            placeholder="Network"
          />
        </label>
        <label className="field">
          <span className="field-label">Severity</span>
          <select value={form.severity} onChange={(event) => update('severity', event.target.value)}>
            {['critical', 'high', 'medium', 'low', 'informational'].map((value) => (
              <option key={value} value={value}>
                {humanize(value)}
              </option>
            ))}
          </select>
        </label>
        <label className="field">
          <span className="field-label">Weight</span>
          <input
            type="number"
            min="0"
            step="0.1"
            value={form.weight}
            onChange={(event) => update('weight', event.target.value)}
          />
          <span className="field-hint">Relative weight used by the scoring model.</span>
        </label>
        <label className="field">
          <span className="field-label">Enabled</span>
          <select
            value={form.isEnabled ? 'yes' : 'no'}
            onChange={(event) => update('isEnabled', event.target.value === 'yes')}
          >
            <option value="yes">Enabled</option>
            <option value="no">Disabled</option>
          </select>
        </label>
        <label className="field span-2">
          <span className="field-label">Description</span>
          <input
            type="text"
            value={form.description}
            onChange={(event) => update('description', event.target.value)}
            placeholder="Why does this override exist?"
          />
        </label>
        <label className="field span-2">
          <span className="field-label">Expected value (JSON)</span>
          <textarea
            value={form.expectedValue}
            onChange={(event) => {
              update('expectedValue', event.target.value);
              setJsonError(null);
            }}
            rows={6}
            spellCheck={false}
            className="mono"
          />
          <span className={jsonError ? 'field-error' : 'field-hint'}>
            {jsonError ?? 'Parsed as JSON before sending. No evaluation is performed in the browser.'}
          </span>
        </label>
        <label className="field span-2">
          <span className="field-label">Recommendation template</span>
          <textarea
            value={form.recommendation}
            onChange={(event) => update('recommendation', event.target.value)}
            rows={3}
            placeholder="Guidance shown with findings for this control."
          />
        </label>
      </div>
    </Drawer>
  );
}

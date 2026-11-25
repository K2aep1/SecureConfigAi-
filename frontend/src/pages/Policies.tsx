/**
 * Policies: baseline overrides.
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

import { useMemo, useState, type ReactNode } from 'react';
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
import { EnabledBadge, NeutralBadge, PolicyLayerBadge, SeverityBadge } from '../components/Badges';
import { Drawer } from '../components/Drawer';
import { EmptyState, ErrorState, Notice } from '../components/States';
import { useConfirm } from '../components/ConfirmDialog';
import { useToast } from '../components/Toast';
import { useSession } from '../auth/SessionProvider';
import { errorToastMessage } from '../lib/errors';
import { formatJsonInline, humanize } from '../lib/format';
import { tryParseJsonValue } from '../lib/json';
import type { EffectiveControl, Policy } from '../types';

/* ---------- Types derived from the API ---------- */

type EffectiveResponse = Awaited<ReturnType<typeof getEffectivePolicies>>;
type ResolvedControl = EffectiveResponse['controls'][number];

interface OverrideForm {
  name: string;
  controlId: string;
  category: string;
  severity: string;
  weight: string;
  description: string;
  expectedValue: string;
  recommendation: string;
  isEnabled: boolean;
}

/* ---------- Constants ---------- */

const PAGE_PARAMS_STALE_MS = 10_000;
const EFFECTIVE_STALE_MS = 30_000;
const SEARCH_DEBOUNCE_MS = 300;

const SEVERITY_CHOICES = ['critical', 'high', 'medium', 'low', 'informational'] as const;
const DEFAULT_EXPECTED_JSON = '{\n  "operator": "==",\n  "value": true\n}';

const EMPTY_FORM: OverrideForm = {
  name: '',
  controlId: '',
  category: '',
  severity: 'medium',
  weight: '1',
  description: '',
  expectedValue: DEFAULT_EXPECTED_JSON,
  recommendation: '',
  isEnabled: true,
};

/* ---------- Pure helpers ---------- */

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

function indexByControl(controls: readonly EffectiveControl[]): Map<string, EffectiveControl> {
  const map = new Map<string, EffectiveControl>();
  for (const control of controls) {
    if (control.control_id) map.set(control.control_id, control);
  }
  return map;
}

function matchesSearch(policy: Policy, needle: string): boolean {
  return `${policy.name} ${policy.control_id} ${policy.category ?? ''} ${policy.description ?? ''}`
    .toLowerCase()
    .includes(needle);
}

/* ---------- Shared presentational pieces ---------- */

/** Baseline value, arrow, then the resolved value (passed as children). */
function BaselineArrow({ baseline, children }: { baseline: ReactNode; children: ReactNode }) {
  return (
    <>
      <span className="resolved-baseline">{baseline}</span>
      <span aria-hidden="true">→</span>
      {children}
    </>
  );
}

function ResolvedComparison({ control }: { control: EffectiveControl | undefined }) {
  if (!control) {
    return <span className="muted">Not present in the resolved control set</span>;
  }

  return (
    <span className="cell-stack resolved">
      <span className="resolved-row">
        <span className="resolved-label">weight</span>
        <BaselineArrow baseline={control.baseline_weight}>
          <strong>{control.weight}</strong>
        </BaselineArrow>
        {control.weight !== control.baseline_weight ? (
          <PolicyLayerBadge layer={control.sources?.weight ?? null} />
        ) : null}
      </span>
      <span className="resolved-row">
        <span className="resolved-label">severity</span>
        <BaselineArrow baseline={humanize(control.baseline_severity)}>
          <strong>{humanize(control.severity)}</strong>
        </BaselineArrow>
        {control.severity !== control.baseline_severity ? (
          <PolicyLayerBadge layer={control.sources?.severity ?? null} />
        ) : null}
      </span>
    </span>
  );
}

/* ---------- Page ---------- */

export default function PoliciesPage() {
  useDocumentTitle('Policies · SecureConfigAI');
  const { isAdmin } = useSession();

  const [includeDisabled, setIncludeDisabled] = useState(true);
  const [showCreate, setShowCreate] = useState(false);

  const effective = useQuery({
    queryKey: queryKeys.policies.effective(),
    enabled: isAdmin,
    staleTime: EFFECTIVE_STALE_MS,
    queryFn: ({ signal }) => getEffectivePolicies(signal),
  });

  const effectiveByControl = useMemo(
    () => indexByControl(effective.data?.controls ?? []),
    [effective.data],
  );

  return (
    <div className="page">
      <PageIntro
        isAdmin={isAdmin}
        onCreate={() => setShowCreate(true)}
        onRefresh={() => void 0}
      />

      {!isAdmin ? <ReadOnlyNotice /> : null}

      <OverridesPanel
        isAdmin={isAdmin}
        includeDisabled={includeDisabled}
        onIncludeDisabledChange={setIncludeDisabled}
        effectiveByControl={effectiveByControl}
        onCreate={() => setShowCreate(true)}
        effectiveError={isAdmin && effective.isError ? effective : null}
      />

      {isAdmin ? <ResolvedSetPanel query={effective} /> : null}

      <CreatePolicyDrawer open={showCreate} onClose={() => setShowCreate(false)} />
    </div>
  );
}

/* ---------- Sections ---------- */

function PageIntro({
  isAdmin,
  onCreate,
  onRefresh,
}: {
  isAdmin: boolean;
  onCreate: () => void;
  onRefresh: () => void;
}) {
  return (
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
        <button type="button" className="button button-light" onClick={onRefresh}>
          Refresh
        </button>
        {isAdmin ? (
          <button type="button" className="button button-primary" onClick={onCreate}>
            New override
          </button>
        ) : null}
      </div>
    </div>
  );
}

function ReadOnlyNotice() {
  return (
    <Notice tone="info" title="Read-only view">
      Creating, enabling, disabling and deleting overrides are administrator actions, and
      `GET /policies/effective` is admin-only, so resolved baseline values are not shown. The API
      will also refuse these writes with a 403.
    </Notice>
  );
}

function OverridesPanel({
  isAdmin,
  includeDisabled,
  onIncludeDisabledChange,
  effectiveByControl,
  onCreate,
  effectiveError,
}: {
  isAdmin: boolean;
  includeDisabled: boolean;
  onIncludeDisabledChange: (value: boolean) => void;
  effectiveByControl: Map<string, EffectiveControl>;
  onCreate: () => void;
  effectiveError: { error: unknown; refetch: () => unknown } | null;
}) {
  const [search, setSearch] = useState('');
  const debouncedSearch = useDebouncedValue(search, SEARCH_DEBOUNCE_MS);

  const params = { limit: DEFAULT_PAGE_SIZE, include_disabled: includeDisabled };

  const policies = useCursorList<Policy>({
    queryKey: queryKeys.policies.list(params),
    fetchPage: (cursor, signal) => listPolicies({ ...params, cursor }, signal),
    staleTime: PAGE_PARAMS_STALE_MS,
  });

  const mutations = usePolicyMutations(isAdmin);

  const rows = useMemo(() => {
    const needle = debouncedSearch.trim().toLowerCase();
    if (!needle) return policies.items;
    return policies.items.filter((policy) => matchesSearch(policy, needle));
  }, [policies.items, debouncedSearch]);

  const columns = useMemo(
    () =>
      buildOverrideColumns({
        isAdmin,
        effectiveByControl,
        toggling: mutations.toggle.isPending,
        removing: mutations.remove.isPending,
        onToggle: (policy) => mutations.toggle.mutate(policy.id),
        onDelete: (policy) => void mutations.requestDelete(policy),
      }),
    [isAdmin, effectiveByControl, mutations],
  );

  return (
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
              onChange={(event) => onIncludeDisabledChange(event.target.checked)}
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
              <OverridesEmpty
                noneDefined={policies.items.length === 0}
                isAdmin={isAdmin}
                onCreate={onCreate}
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

      {effectiveError ? (
        <ErrorState
          error={effectiveError.error}
          onRetry={() => void effectiveError.refetch()}
          scope="Resolved control set"
          compact
        />
      ) : null}
    </section>
  );
}

function OverridesEmpty({
  noneDefined,
  isAdmin,
  onCreate,
}: {
  noneDefined: boolean;
  isAdmin: boolean;
  onCreate: () => void;
}) {
  return (
    <EmptyState
      title={noneDefined ? 'No overrides defined' : 'No overrides match this search'}
      description={
        noneDefined
          ? 'The baseline applies unchanged. Create an override to deviate for specific controls.'
          : 'Clear the search box to see every loaded override.'
      }
      action={
        isAdmin && noneDefined ? (
          <button type="button" className="button button-primary" onClick={onCreate}>
            Create the first override
          </button>
        ) : null
      }
    />
  );
}

function ResolvedSetPanel({ query }: { query: ReturnType<typeof useQuery<EffectiveResponse>> }) {
  const controls = query.data?.controls ?? [];

  return (
    <section className="panel">
      <div className="panel-head">
        <div>
          <h2>Resolved control set</h2>
          <p>
            {query.data
              ? `${controls.length} controls resolved from baseline ${query.data.baseline_id} v${query.data.baseline_version} · total weight ${query.data.total_weight}.`
              : 'Loading the resolved control set…'}
          </p>
        </div>
      </div>

      {query.data && controls.length === 0 ? (
        <EmptyState
          title="Nothing resolved"
          description="The API returned an empty resolved control set."
          compact
        />
      ) : null}

      {controls.length > 0 ? (
        <DataTable
          columns={RESOLVED_COLUMNS}
          rows={controls}
          rowKey={(row) => row.control_id}
          caption="Resolved control set"
          empty={<EmptyState title="Nothing resolved" compact />}
        />
      ) : null}
    </section>
  );
}

/* ---------- Mutations ---------- */

/** Toggle and delete for existing overrides. Both report through toasts and refresh the caches. */
function usePolicyMutations(isAdmin: boolean) {
  const toast = useToast();
  const confirm = useConfirm();
  const queryClient = useQueryClient();

  function invalidate() {
    void queryClient.invalidateQueries({ queryKey: queryKeys.policies.all });
    if (isAdmin) void queryClient.invalidateQueries({ queryKey: queryKeys.policies.effective() });
  }

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
      invalidate();
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
      invalidate();
    },
    onError: (error) => {
      toast.push({
        tone: 'error',
        title: 'Could not delete the override',
        message: errorToastMessage(error),
      });
    },
  });

  async function requestDelete(policy: Policy) {
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

  return { toggle, remove, requestDelete };
}

/* ---------- Override table columns ---------- */

function buildOverrideColumns({
  isAdmin,
  effectiveByControl,
  toggling,
  removing,
  onToggle,
  onDelete,
}: {
  isAdmin: boolean;
  effectiveByControl: Map<string, EffectiveControl>;
  toggling: boolean;
  removing: boolean;
  onToggle: (policy: Policy) => void;
  onDelete: (policy: Policy) => void;
}): Column<Policy>[] {
  return [
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
      cell: (row) => <code className="cell-code">{row.control_id}</code>,
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
      cell: (row) =>
        isAdmin ? (
          <ResolvedComparison control={effectiveByControl.get(row.control_id)} />
        ) : (
          <span className="muted">admin only</span>
        ),
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
              onClick={() => onToggle(row)}
              disabled={toggling}
            >
              {row.is_enabled ? 'Disable' : 'Enable'}
            </button>
            <button
              type="button"
              className="text-button danger-text"
              onClick={() => onDelete(row)}
              disabled={removing}
            >
              Delete
            </button>
          </span>
        ) : (
          <span className="muted">read-only</span>
        ),
    },
  ];
}

/* ---------- Resolved set columns (no dependencies, built once) ---------- */

const RESOLVED_COLUMNS: Column<ResolvedControl>[] = [
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
        <BaselineArrow baseline={row.baseline_weight}>
          <strong>{row.weight}</strong>
        </BaselineArrow>
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
        <BaselineArrow baseline={humanize(row.baseline_severity)}>
          <SeverityBadge severity={row.severity} />
        </BaselineArrow>
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
        <NeutralBadge
          label="Exempt"
          title={row.exemption_reason ?? 'An exemption applies on this device.'}
        />
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
];

/* ---------- Create drawer ---------- */

function CreatePolicyDrawer({ open, onClose }: { open: boolean; onClose: () => void }) {
  const toast = useToast();
  const queryClient = useQueryClient();
  const [form, setForm] = useState<OverrideForm>(EMPTY_FORM);
  const [jsonError, setJsonError] = useState<string | null>(null);

  const set = <K extends keyof OverrideForm>(key: K) => (value: OverrideForm[K]) =>
    setForm((current) => ({ ...current, [key]: value }));

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

  const canSubmit =
    !create.isPending && form.name.trim() !== '' && form.controlId.trim() !== '';

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
            disabled={!canSubmit}
          >
            {create.isPending ? 'Creating…' : 'Create override'}
          </button>
        </div>
      }
    >
      <div className="form-grid">
        <TextField
          label="Name"
          value={form.name}
          onChange={set('name')}
          placeholder="Stricter SMB signing requirement"
          required
        />
        <TextField
          label="Control ID"
          value={form.controlId}
          onChange={set('controlId')}
          placeholder="WIN-SMB-002"
          required
        />
        <TextField label="Category" value={form.category} onChange={set('category')} placeholder="Network" />
        <label className="field">
          <span className="field-label">Severity</span>
          <select value={form.severity} onChange={(event) => set('severity')(event.target.value)}>
            {SEVERITY_CHOICES.map((value) => (
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
            onChange={(event) => set('weight')(event.target.value)}
          />
          <span className="field-hint">Relative weight used by the scoring model.</span>
        </label>
        <label className="field">
          <span className="field-label">Enabled</span>
          <select
            value={form.isEnabled ? 'yes' : 'no'}
            onChange={(event) => set('isEnabled')(event.target.value === 'yes')}
          >
            <option value="yes">Enabled</option>
            <option value="no">Disabled</option>
          </select>
        </label>
        <TextField
          label="Description"
          value={form.description}
          onChange={set('description')}
          placeholder="Why does this override exist?"
          spanTwo
        />
        <label className="field span-2">
          <span className="field-label">Expected value (JSON)</span>
          <textarea
            value={form.expectedValue}
            onChange={(event) => {
              set('expectedValue')(event.target.value);
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
            onChange={(event) => set('recommendation')(event.target.value)}
            rows={3}
            placeholder="Guidance shown with findings for this control."
          />
        </label>
      </div>
    </Drawer>
  );
}

function TextField({
  label,
  value,
  onChange,
  placeholder,
  required,
  spanTwo,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  required?: boolean;
  spanTwo?: boolean;
}) {
  return (
    <label className={spanTwo ? 'field span-2' : 'field'}>
      <span className="field-label">{label}</span>
      <input
        type="text"
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        required={required}
      />
    </label>
  );
}
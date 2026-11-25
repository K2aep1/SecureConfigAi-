/**
 * Devices.
 *
 * `criticality` (1..5) is editable inline, with the contract's labels and an
 * explicit statement of what it does: it scales the risk calculation, nothing
 * else. Each row also shows the latest assessment's score, risk, coverage and
 * evidence quality, so a device's posture is readable without opening a scan.
 *
 * Per-device exemptions live in a drawer (contract §5): creating one marks the
 * control `not_applicable` with the recorded reason.
 */

import { useEffect, useMemo, useState, type ReactNode } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  createDeviceExemption,
  deleteDevice,
  deleteDeviceExemption,
  listDeviceExemptions,
  listDevices,
  queryKeys,
  registerDevice,
  updateDevice,
} from '../api';
import { DEFAULT_PAGE_SIZE, useCursorList } from '../hooks/useCursorList';
import { useDocumentTitle } from '../hooks/useAppData';
import { DataTable, LoadMore, type Column } from '../components/DataTable';
import { EvidenceQualityBadge, NeutralBadge, RiskLevelBadge } from '../components/Badges';
import { Drawer } from '../components/Drawer';
import { EmptyState, ErrorState, Notice } from '../components/States';
import { useConfirm } from '../components/ConfirmDialog';
import { useToast } from '../components/Toast';
import { useSession } from '../auth/SessionProvider';
import { errorToastMessage } from '../lib/errors';
import { CRITICALITY_CHOICES, CRITICALITY_EXPLANATION, criticalityChoice } from '../lib/verdict';
import { formatDateTime, formatPercent, formatRelative, formatScore } from '../lib/format';
import type { Device, Exemption } from '../types';

/* ---------- Constants ---------- */

const DEVICES_STALE_MS = 15_000;
const EXEMPTIONS_STALE_MS = 30_000;
const DEFAULT_OS_TYPE = 'windows';
const DEFAULT_CRITICALITY = '3';

interface RegisterDraft {
  hostname: string;
  osType: string;
  osVersion: string;
  osBuild: string;
  criticality: string;
}

interface ExemptionDraft {
  controlId: string;
  reason: string;
  expiresAt: string;
}

const EMPTY_EXEMPTION: ExemptionDraft = { controlId: '', reason: '', expiresAt: '' };

/* ---------- Pure helpers ---------- */

function scoreCell(device: Device): ReactNode {
  const score = device.latest?.security_score;
  if (score === null || score === undefined) {
    return (
      <span className="muted" title="This device has no completed assessment yet.">
        not assessed
      </span>
    );
  }
  return `${formatScore(score)}/100`;
}

function riskCell(device: Device): ReactNode {
  const latest = device.latest;
  if (!latest) return <span className="muted">—</span>;
  return (
    <span className="cell-stack">
      <RiskLevelBadge level={latest.risk_level} score={latest.risk_score} />
      <span className="cell-subtle">risk score {formatScore(latest.risk_score)}</span>
    </span>
  );
}

function evidenceCell(device: Device): ReactNode {
  return device.latest ? (
    <EvidenceQualityBadge quality={device.latest.evidence_quality} />
  ) : (
    <span className="muted">—</span>
  );
}

function criticalityOptionLabel(option: (typeof CRITICALITY_CHOICES)[number]): string {
  return `${option.value} · ${option.label}`;
}

/* ---------- Page ---------- */

export default function DevicesPage() {
  useDocumentTitle('Devices · SecureConfigAI');

  const devices = useCursorList<Device>({
    queryKey: queryKeys.devices.list(),
    fetchPage: (cursor, signal) => listDevices({ limit: DEFAULT_PAGE_SIZE, cursor }, signal),
    staleTime: DEVICES_STALE_MS,
  });

  const [exemptionsFor, setExemptionsFor] = useState<Device | null>(null);
  const [showRegister, setShowRegister] = useState(false);
  const { remove, requestRemove } = useDeviceRemoval();

  const columns = useMemo(
    () =>
      buildDeviceColumns({
        removing: remove.isPending,
        onExemptions: setExemptionsFor,
        onRemove: (device) => void requestRemove(device),
      }),
    [remove.isPending, requestRemove],
  );

  return (
    <div className="page">
      <PageIntro
        onRefresh={devices.reload}
        onRegister={() => setShowRegister(true)}
      />

      <Notice tone="info" title="How criticality is used">
        {CRITICALITY_EXPLANATION}
      </Notice>

      <DeviceInventory
        devices={devices}
        columns={columns}
        onRegister={() => setShowRegister(true)}
      />

      <RegisterDeviceDrawer open={showRegister} onClose={() => setShowRegister(false)} />
      <DeviceExemptionsDrawer device={exemptionsFor} onClose={() => setExemptionsFor(null)} />
    </div>
  );
}

/* ---------- Sections ---------- */

function PageIntro({
  onRefresh,
  onRegister,
}: {
  onRefresh: () => void;
  onRegister: () => void;
}) {
  return (
    <div className="page-intro">
      <div>
        <span className="eyebrow">Endpoint inventory</span>
        <h2>Devices</h2>
        <p>
          Registered endpoints with their most recent assessed posture. Criticality is an input to
          the risk calculation, not to the control verdicts.
        </p>
      </div>
      <div className="inline-actions">
        <button type="button" className="button button-light" onClick={onRefresh}>
          Refresh
        </button>
        <button type="button" className="button button-primary" onClick={onRegister}>
          Register device
        </button>
      </div>
    </div>
  );
}

function DeviceInventory({
  devices,
  columns,
  onRegister,
}: {
  devices: ReturnType<typeof useCursorList<Device>>;
  columns: Column<Device>[];
  onRegister: () => void;
}) {
  return (
    <section className="panel">
      <div className="panel-head">
        <div>
          <h2>Registered devices</h2>
          <p>
            {devices.count} loaded{devices.hasMore ? ' · more available' : ''}
          </p>
        </div>
      </div>

      {devices.isError ? (
        <ErrorState error={devices.error} onRetry={devices.reload} scope="Device inventory" />
      ) : (
        <>
          <DataTable
            columns={columns}
            rows={devices.items}
            rowKey={(row) => row.id}
            caption="Registered devices"
            busy={devices.isLoading}
            busyLabel="Loading devices…"
            empty={
              <EmptyState
                title="No devices registered"
                description="A device is registered automatically by its first scan, or manually with POST /devices/register."
                action={
                  <button type="button" className="button button-primary" onClick={onRegister}>
                    Register device
                  </button>
                }
              />
            }
          />
          <LoadMore
            hasMore={devices.hasMore}
            isLoading={devices.isLoadingMore}
            onLoadMore={devices.loadMore}
            loadedCount={devices.count}
            pageSize={DEFAULT_PAGE_SIZE}
            unit="devices"
          />
        </>
      )}
    </section>
  );
}

/* ---------- Device removal ---------- */

function useDeviceRemoval() {
  const toast = useToast();
  const confirm = useConfirm();
  const queryClient = useQueryClient();

  const remove = useMutation({
    mutationFn: (deviceId: string) => deleteDevice(deviceId),
    onSuccess: () => {
      toast.push({ tone: 'success', title: 'Device removed' });
      void queryClient.invalidateQueries({ queryKey: queryKeys.devices.all });
    },
    onError: (error) => {
      toast.push({
        tone: 'error',
        title: 'Could not remove the device',
        message: errorToastMessage(error),
      });
    },
  });

  async function requestRemove(device: Device) {
    const confirmed = await confirm({
      title: `Remove ${device.hostname}?`,
      message:
        'The device is removed from the inventory and its scan history is detached. Past scans survive as unlinked records.',
      confirmLabel: 'Remove device',
      destructive: true,
    });
    if (confirmed) remove.mutate(device.id);
  }

  return { remove, requestRemove };
}

/* ---------- Inventory columns ---------- */

function buildDeviceColumns({
  removing,
  onExemptions,
  onRemove,
}: {
  removing: boolean;
  onExemptions: (device: Device) => void;
  onRemove: (device: Device) => void;
}): Column<Device>[] {
  return [
    {
      id: 'hostname',
      header: 'Device',
      width: '18%',
      cell: (row) => (
        <span className="cell-stack">
          <span className="cell-title">{row.hostname}</span>
          <code className="cell-code">{row.id}</code>
        </span>
      ),
    },
    {
      id: 'os',
      header: 'Operating system',
      width: '16%',
      cell: (row) => (
        <span className="cell-stack">
          <span>
            {row.os_type} {row.os_version ?? ''}
          </span>
          <span className="cell-subtle mono">{row.os_build ?? 'build unknown'}</span>
        </span>
      ),
    },
    {
      id: 'criticality',
      header: 'Criticality',
      width: '16%',
      cell: (row) => <CriticalityEditor device={row} />,
    },
    {
      id: 'score',
      header: 'Latest score',
      align: 'right',
      width: '11%',
      cell: scoreCell,
    },
    {
      id: 'risk',
      header: 'Risk',
      width: '13%',
      cell: riskCell,
    },
    {
      id: 'coverage',
      header: 'Coverage',
      align: 'right',
      hideBelow: 'lg',
      width: '10%',
      cell: (row) => formatPercent(row.latest?.assessment_coverage),
    },
    {
      id: 'evidence',
      header: 'Evidence',
      hideBelow: 'lg',
      width: '11%',
      cell: evidenceCell,
    },
    {
      id: 'lastScan',
      header: 'Last scan',
      hideBelow: 'md',
      width: '13%',
      cell: (row) => (
        <span className="cell-stack">
          <span>{formatRelative(row.last_scan_at)}</span>
          <span className="cell-subtle">
            {row.scan_count} scan{row.scan_count === 1 ? '' : 's'}
          </span>
        </span>
      ),
    },
    {
      id: 'actions',
      header: 'Actions',
      align: 'right',
      width: '13%',
      cell: (row) => (
        <span className="inline-actions">
          <button type="button" className="text-button" onClick={() => onExemptions(row)}>
            Exemptions
          </button>
          <button
            type="button"
            className="text-button danger-text"
            onClick={() => onRemove(row)}
            disabled={removing}
          >
            Remove
          </button>
        </span>
      ),
    },
  ];
}

/* ---------- Criticality ---------- */

/** Inline `PUT /devices/{id}` editor for the 1..5 criticality scale. */
function CriticalityEditor({ device }: { device: Device }) {
  const toast = useToast();
  const queryClient = useQueryClient();
  const choice = criticalityChoice(device.criticality);

  const update = useMutation({
    mutationFn: (criticality: number) => updateDevice(device.id, { criticality }),
    onSuccess: (updated) => {
      toast.push({
        tone: 'success',
        title: `${updated.hostname} criticality set to ${criticalityChoice(updated.criticality)?.label ?? updated.criticality}`,
        message: 'The next assessment will weight its findings with this value.',
      });
      void queryClient.invalidateQueries({ queryKey: queryKeys.devices.all });
    },
    onError: (error) => {
      toast.push({
        tone: 'error',
        title: 'Could not update criticality',
        message: errorToastMessage(error),
      });
    },
  });

  const inputId = `criticality-${device.id}`;

  return (
    <span className="criticality-editor">
      <label className="visually-hidden" htmlFor={inputId}>
        Criticality for {device.hostname}
      </label>
      <select
        id={inputId}
        value={String(device.criticality)}
        disabled={update.isPending}
        title={CRITICALITY_EXPLANATION}
        onChange={(event) => update.mutate(Number(event.target.value))}
      >
        {CRITICALITY_CHOICES.map((option) => (
          <option key={option.value} value={option.value}>
            {criticalityOptionLabel(option)}
          </option>
        ))}
      </select>
      <span className="criticality-note" title={CRITICALITY_EXPLANATION}>
        {choice ? `risk weight ×${choice.value}` : 'unknown value — expected 1..5'}
      </span>
    </span>
  );
}

/* ---------- Register drawer ---------- */

const EMPTY_REGISTER_DRAFT: RegisterDraft = {
  hostname: '',
  osType: DEFAULT_OS_TYPE,
  osVersion: '',
  osBuild: '',
  criticality: DEFAULT_CRITICALITY,
};

function RegisterDeviceDrawer({ open, onClose }: { open: boolean; onClose: () => void }) {
  const toast = useToast();
  const queryClient = useQueryClient();
  const [draft, setDraft] = useState<RegisterDraft>(EMPTY_REGISTER_DRAFT);

  const set = <K extends keyof RegisterDraft>(key: K) => (value: RegisterDraft[K]) =>
    setDraft((current) => ({ ...current, [key]: value }));

  const register = useMutation({
    mutationFn: () =>
      registerDevice({
        hostname: draft.hostname.trim(),
        os_type: draft.osType.trim() || undefined,
        os_version: draft.osVersion.trim() || undefined,
        os_build: draft.osBuild.trim() || undefined,
        criticality: Number(draft.criticality),
      }),
    onSuccess: (device) => {
      toast.push({
        tone: 'success',
        title: `${device.hostname} registered`,
        message: 'Registering upserts by hostname: an existing host is updated, not duplicated.',
      });
      void queryClient.invalidateQueries({ queryKey: queryKeys.devices.all });
      // Matches the previous behaviour: hostname and OS details clear, OS type and criticality persist.
      setDraft((current) => ({ ...current, hostname: '', osVersion: '', osBuild: '' }));
      onClose();
    },
    onError: (error) => {
      toast.push({
        tone: 'error',
        title: 'Could not register the device',
        message: errorToastMessage(error),
      });
    },
  });

  const canSubmit = !register.isPending && draft.hostname.trim().length > 0;

  return (
    <Drawer
      open={open}
      onClose={onClose}
      title="Register a device"
      subtitle="Upserts by hostname — registering a known host updates its recorded details."
      footer={
        <div className="inline-actions inline-actions-end">
          <button type="button" className="button button-light" onClick={onClose}>
            Cancel
          </button>
          <button
            type="button"
            className="button button-primary"
            onClick={() => register.mutate()}
            disabled={!canSubmit}
          >
            {register.isPending ? 'Registering…' : 'Register device'}
          </button>
        </div>
      }
    >
      <div className="form-grid">
        <TextField label="Hostname" value={draft.hostname} onChange={set('hostname')} placeholder="WIN-DEV-01" required />
        <TextField label="OS type" value={draft.osType} onChange={set('osType')} />
        <TextField label="OS version" value={draft.osVersion} onChange={set('osVersion')} placeholder="Windows 11 Pro" />
        <TextField label="OS build" value={draft.osBuild} onChange={set('osBuild')} placeholder="26100.1742" />
        <label className="field">
          <span className="field-label">Criticality</span>
          <select value={draft.criticality} onChange={(event) => set('criticality')(event.target.value)}>
            {CRITICALITY_CHOICES.map((option) => (
              <option key={option.value} value={option.value}>
                {criticalityOptionLabel(option)}
              </option>
            ))}
          </select>
          <span className="field-hint">{CRITICALITY_EXPLANATION}</span>
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
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  required?: boolean;
}) {
  return (
    <label className="field">
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

/* ---------- Exemptions drawer ---------- */

function DeviceExemptionsDrawer({
  device,
  onClose,
}: {
  device: Device | null;
  onClose: () => void;
}) {
  const { isAdmin } = useSession();
  const exemptions = useDeviceExemptions(device);
  const [draft, setDraft] = useState<ExemptionDraft>(EMPTY_EXEMPTION);

  // Never carry an unfinished exemption from one device to another.
  // Closing the drawer also clears the draft because `device` becomes null.
  useEffect(() => {
    setDraft(EMPTY_EXEMPTION);
  }, [device?.id]);

  const { create, remove, requestRemove } = useExemptionMutations(device, () =>
    setDraft(EMPTY_EXEMPTION),
  );

  const expiresAtMs = draft.expiresAt ? new Date(draft.expiresAt).getTime() : null;
  const invalidExpiry =
    expiresAtMs !== null && (!Number.isFinite(expiresAtMs) || expiresAtMs <= Date.now());
  const canRecord =
    draft.controlId.trim() !== '' &&
    draft.reason.trim() !== '' &&
    !invalidExpiry;

  return (
    <Drawer
      open={device !== null}
      onClose={onClose}
      width="wide"
      title={device ? `Exemptions · ${device.hostname}` : 'Exemptions'}
      subtitle="Exempted controls report not_applicable and are excluded from scoring, with the reason kept on record."
    >
      <div className="drawer-sections">
        {isAdmin ? (
          <ExemptionForm
            draft={draft}
            onChange={setDraft}
            onSubmit={() => create.mutate(draft)}
            busy={create.isPending}
            disabled={!canRecord}
            invalidExpiry={invalidExpiry}
          />
        ) : (
          <Notice tone="info" title="Read-only">
            Recording or removing exemptions is an administrator action. You can still review the
            exemptions recorded for this device.
          </Notice>
        )}

        <ExemptionList
          query={exemptions}
          isAdmin={isAdmin}
          removing={remove.isPending}
          onRemove={requestRemove}
        />
      </div>
    </Drawer>
  );
}

function useDeviceExemptions(device: Device | null) {
  return useQuery({
    queryKey: queryKeys.devices.exemptions(device?.id ?? 'none'),
    enabled: device !== null,
    staleTime: EXEMPTIONS_STALE_MS,
    queryFn: ({ signal }) => {
      if (!device) throw new Error('No device selected.');
      return listDeviceExemptions(device.id, signal);
    },
  });
}

function useExemptionMutations(device: Device | null, onRecorded: () => void) {
  const toast = useToast();
  const confirm = useConfirm();
  const queryClient = useQueryClient();

  const create = useMutation({
    mutationFn: (draft: ExemptionDraft) => {
      if (!device) throw new Error('No device selected.');
      return createDeviceExemption(device.id, {
        control_id: draft.controlId.trim(),
        reason: draft.reason.trim(),
        expires_at: draft.expiresAt ? new Date(draft.expiresAt).toISOString() : undefined,
      });
    },
    onSuccess: () => {
      toast.push({
        tone: 'success',
        title: 'Exemption recorded',
        message: 'The control now reports not_applicable on this device, with the reason attached.',
      });
      onRecorded();
      if (device) {
        void queryClient.invalidateQueries({
          queryKey: queryKeys.devices.exemptions(device.id),
        });
      }
      void queryClient.invalidateQueries({ queryKey: queryKeys.devices.all });
    },
    onError: (error) => {
      toast.push({
        tone: 'error',
        title: 'Could not record the exemption',
        message: errorToastMessage(error),
      });
    },
  });

  const remove = useMutation({
    mutationFn: (exemptControlId: string) => {
      if (!device) throw new Error('No device selected.');
      return deleteDeviceExemption(device.id, exemptControlId);
    },
    onSuccess: () => {
      toast.push({ tone: 'success', title: 'Exemption removed' });
      if (device) {
        void queryClient.invalidateQueries({
          queryKey: queryKeys.devices.exemptions(device.id),
        });
      }
      void queryClient.invalidateQueries({ queryKey: queryKeys.devices.all });
    },
    onError: (error) => {
      toast.push({
        tone: 'error',
        title: 'Could not remove the exemption',
        message: errorToastMessage(error),
      });
    },
  });

  async function requestRemove(exemption: Exemption) {
    const confirmed = await confirm({
      title: 'Remove this exemption?',
      message: (
        <>
          <code>{exemption.control_id}</code> returns to normal evaluation on this device.
        </>
      ),
      confirmLabel: 'Remove exemption',
      destructive: true,
    });
    if (confirmed) remove.mutate(exemption.control_id);
  }

  return { create, remove, requestRemove };
}

function ExemptionForm({
  draft,
  onChange,
  onSubmit,
  busy,
  disabled,
  invalidExpiry,
}: {
  draft: ExemptionDraft;
  onChange: (next: ExemptionDraft) => void;
  onSubmit: () => void;
  busy: boolean;
  disabled: boolean;
  invalidExpiry: boolean;
}) {
  const set = (key: keyof ExemptionDraft) => (value: string) => onChange({ ...draft, [key]: value });

  return (
    <section className="drawer-section">
      <h3 className="drawer-section-title">Record an exemption</h3>
      <div className="form-grid">
        <label className="field">
          <span className="field-label">Control ID</span>
          <input
            type="text"
            value={draft.controlId}
            onChange={(event) => set('controlId')(event.target.value)}
            placeholder="e.g. WIN-FW-001"
          />
        </label>
        <label className="field">
          <span className="field-label">Expires at (optional)</span>
          <input
            type="datetime-local"
            value={draft.expiresAt}
            min={toLocalDateTimeInputValue(new Date())}
            onChange={(event) => set('expiresAt')(event.target.value)}
            aria-invalid={invalidExpiry}
          />
          {invalidExpiry ? (
            <span className="field-hint" role="alert">
              Expiration must be a valid date and time in the future.
            </span>
          ) : null}
        </label>
        <label className="field span-2">
          <span className="field-label">Reason</span>
          <textarea
            value={draft.reason}
            onChange={(event) => set('reason')(event.target.value)}
            rows={3}
            placeholder="Why does this control not apply to this device?"
          />
        </label>
      </div>
      <button type="button" className="button button-primary" onClick={onSubmit} disabled={busy || disabled}>
        {busy ? 'Recording…' : 'Record exemption'}
      </button>
    </section>
  );
}

function toLocalDateTimeInputValue(date: Date): string {
  const local = new Date(date.getTime() - date.getTimezoneOffset() * 60_000);
  return local.toISOString().slice(0, 16);
}

function exemptionExpiryCell(exemption: Exemption): ReactNode {
  if (!exemption.expires_at) {
    return <NeutralBadge label="No expiry" title="This exemption does not expire." />;
  }

  const expiresAt = new Date(exemption.expires_at);
  if (!Number.isFinite(expiresAt.getTime())) {
    return <span className="muted">Invalid expiry date</span>;
  }

  const expired = expiresAt.getTime() <= Date.now();

  return (
    <span className="cell-stack">
      <span>{formatDateTime(exemption.expires_at)}</span>
      <span className="cell-subtle">{expired ? 'Expired' : 'Active'}</span>
    </span>
  );
}

function ExemptionList({
  query,
  isAdmin,
  removing,
  onRemove,
}: {
  query: ReturnType<typeof useDeviceExemptions>;
  isAdmin: boolean;
  removing: boolean;
  onRemove: (exemption: Exemption) => void;
}) {
  const columns: Column<Exemption>[] = [
    {
      id: 'control',
      header: 'Control',
      cell: (row) => <code className="cell-code">{row.control_id}</code>,
    },
    {
      id: 'reason',
      header: 'Reason',
      cell: (row) => row.reason ?? <span className="muted">—</span>,
    },
    {
      id: 'expires',
      header: 'Expires',
      width: '18%',
      cell: exemptionExpiryCell,
    },
    {
      id: 'actions',
      header: '',
      align: 'right',
      width: '12%',
      cell: (row) =>
        isAdmin ? (
          <button
            type="button"
            className="text-button danger-text"
            onClick={() => onRemove(row)}
            disabled={removing}
          >
            Remove
          </button>
        ) : null,
    },
  ];

  return (
    <section className="drawer-section">
      <h3 className="drawer-section-title">Current exemptions</h3>

      {query.isLoading ? <EmptyState title="Loading exemptions…" compact /> : null}
      {query.isError ? (
        <ErrorState error={query.error} onRetry={() => void query.refetch()} scope="Exemptions" compact />
      ) : null}
      {query.data && query.data.length === 0 ? (
        <EmptyState
          title="No exemptions recorded"
          description="Every control in the baseline is evaluated normally on this device."
          compact
        />
      ) : null}
      {query.data && query.data.length > 0 ? (
        <DataTable
          columns={columns}
          rows={query.data}
          rowKey={(row) => row.control_id}
          caption="Per-device control exemptions"
          empty={<EmptyState title="No exemptions" compact />}
        />
      ) : null}
    </section>
  );
}
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

import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  createDeviceExemption,
  deleteDeviceExemption,
  deleteDevice,
  listDeviceExemptions,
  listDevices,
  queryKeys,
  registerDevice,
  updateDevice,
} from '../api';
import { DEFAULT_PAGE_SIZE, useCursorList } from '../hooks/useCursorList';
import { useDocumentTitle } from '../hooks/useAppData';
import { DataTable, LoadMore, type Column } from '../components/DataTable';
import { EvidenceQualityBadge, RiskLevelBadge, NeutralBadge } from '../components/Badges';
import { Drawer } from '../components/Drawer';
import { EmptyState, ErrorState, Notice } from '../components/States';
import { useConfirm } from '../components/ConfirmDialog';
import { useToast } from '../components/Toast';
import { useSession } from '../auth/SessionProvider';
import { errorToastMessage } from '../lib/errors';
import { CRITICALITY_CHOICES, CRITICALITY_EXPLANATION, criticalityChoice } from '../lib/verdict';
import { formatDateTime, formatPercent, formatRelative, formatScore } from '../lib/format';
import type { Device, Exemption } from '../types';

export default function DevicesPage() {
  useDocumentTitle('Devices · SecureConfigAI');
  const toast = useToast();
  const confirm = useConfirm();
  const queryClient = useQueryClient();
  const [exemptionsFor, setExemptionsFor] = useState<Device | null>(null);
  const [showRegister, setShowRegister] = useState(false);

  const devices = useCursorList<Device>({
    queryKey: queryKeys.devices.list(),
    fetchPage: (cursor, signal) => listDevices({ limit: DEFAULT_PAGE_SIZE, cursor }, signal),
    staleTime: 15_000,
  });

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

  async function onRemove(device: Device) {
    const confirmed = await confirm({
      title: `Remove ${device.hostname}?`,
      message:
        'The device is removed from the inventory and its scan history is detached. Past scans survive as unlinked records.',
      confirmLabel: 'Remove device',
      destructive: true,
    });
    if (confirmed) remove.mutate(device.id);
  }

  const columns: Column<Device>[] = [
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
      cell: (row) =>
        row.latest?.security_score === null || row.latest?.security_score === undefined ? (
          <span className="muted" title="This device has no completed assessment yet.">
            not assessed
          </span>
        ) : (
          `${formatScore(row.latest.security_score)}/100`
        ),
    },
    {
      id: 'risk',
      header: 'Risk',
      width: '13%',
      cell: (row) =>
        row.latest ? (
          <span className="cell-stack">
            <RiskLevelBadge level={row.latest.risk_level} score={row.latest.risk_score} />
            <span className="cell-subtle">risk score {formatScore(row.latest.risk_score)}</span>
          </span>
        ) : (
          <span className="muted">—</span>
        ),
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
      cell: (row) =>
        row.latest ? (
          <EvidenceQualityBadge quality={row.latest.evidence_quality} />
        ) : (
          <span className="muted">—</span>
        ),
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
          <button type="button" className="text-button" onClick={() => setExemptionsFor(row)}>
            Exemptions
          </button>
          <button
            type="button"
            className="text-button danger-text"
            onClick={() => void onRemove(row)}
            disabled={remove.isPending}
          >
            Remove
          </button>
        </span>
      ),
    },
  ];

  return (
    <div className="page">
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
          <button type="button" className="button button-light" onClick={devices.reload}>
            Refresh
          </button>
          <button
            type="button"
            className="button button-primary"
            onClick={() => setShowRegister(true)}
          >
            Register device
          </button>
        </div>
      </div>

      <Notice tone="info" title="How criticality is used">
        {CRITICALITY_EXPLANATION}
      </Notice>

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
                    <button
                      type="button"
                      className="button button-primary"
                      onClick={() => setShowRegister(true)}
                    >
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

      <RegisterDeviceDrawer open={showRegister} onClose={() => setShowRegister(false)} />
      <DeviceExemptionsDrawer device={exemptionsFor} onClose={() => setExemptionsFor(null)} />
    </div>
  );
}

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

  return (
    <span className="criticality-editor">
      <label className="visually-hidden" htmlFor={`criticality-${device.id}`}>
        Criticality for {device.hostname}
      </label>
      <select
        id={`criticality-${device.id}`}
        value={String(device.criticality)}
        disabled={update.isPending}
        title={CRITICALITY_EXPLANATION}
        onChange={(event) => update.mutate(Number(event.target.value))}
      >
        {CRITICALITY_CHOICES.map((option) => (
          <option key={option.value} value={option.value}>
            {option.value} · {option.label}
          </option>
        ))}
      </select>
      <span className="criticality-note" title={CRITICALITY_EXPLANATION}>
        {choice ? `risk weight ×${choice.value}` : 'unknown value — expected 1..5'}
      </span>
    </span>
  );
}

function RegisterDeviceDrawer({ open, onClose }: { open: boolean; onClose: () => void }) {
  const toast = useToast();
  const queryClient = useQueryClient();
  const [hostname, setHostname] = useState('');
  const [osType, setOsType] = useState('windows');
  const [osVersion, setOsVersion] = useState('');
  const [osBuild, setOsBuild] = useState('');
  const [criticality, setCriticality] = useState('3');

  const register = useMutation({
    mutationFn: () =>
      registerDevice({
        hostname: hostname.trim(),
        os_type: osType.trim() || undefined,
        os_version: osVersion.trim() || undefined,
        os_build: osBuild.trim() || undefined,
        criticality: Number(criticality),
      }),
    onSuccess: (device) => {
      toast.push({
        tone: 'success',
        title: `${device.hostname} registered`,
        message: 'Registering upserts by hostname: an existing host is updated, not duplicated.',
      });
      void queryClient.invalidateQueries({ queryKey: queryKeys.devices.all });
      setHostname('');
      setOsVersion('');
      setOsBuild('');
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
            disabled={register.isPending || hostname.trim().length === 0}
          >
            {register.isPending ? 'Registering…' : 'Register device'}
          </button>
        </div>
      }
    >
      <div className="form-grid">
        <label className="field">
          <span className="field-label">Hostname</span>
          <input
            type="text"
            value={hostname}
            onChange={(event) => setHostname(event.target.value)}
            placeholder="WIN-DEV-01"
            required
          />
        </label>
        <label className="field">
          <span className="field-label">OS type</span>
          <input type="text" value={osType} onChange={(event) => setOsType(event.target.value)} />
        </label>
        <label className="field">
          <span className="field-label">OS version</span>
          <input
            type="text"
            value={osVersion}
            onChange={(event) => setOsVersion(event.target.value)}
            placeholder="Windows 11 Pro"
          />
        </label>
        <label className="field">
          <span className="field-label">OS build</span>
          <input
            type="text"
            value={osBuild}
            onChange={(event) => setOsBuild(event.target.value)}
            placeholder="26100.1742"
          />
        </label>
        <label className="field">
          <span className="field-label">Criticality</span>
          <select value={criticality} onChange={(event) => setCriticality(event.target.value)}>
            {CRITICALITY_CHOICES.map((option) => (
              <option key={option.value} value={option.value}>
                {option.value} · {option.label}
              </option>
            ))}
          </select>
          <span className="field-hint">{CRITICALITY_EXPLANATION}</span>
        </label>
      </div>
    </Drawer>
  );
}

function DeviceExemptionsDrawer({ device, onClose }: { device: Device | null; onClose: () => void }) {
  const toast = useToast();
  const confirm = useConfirm();
  const queryClient = useQueryClient();
  const { isAdmin } = useSession();
  const [controlId, setControlId] = useState('');
  const [reason, setReason] = useState('');
  const [expiresAt, setExpiresAt] = useState('');

  const exemptions = useQuery({
    queryKey: queryKeys.devices.exemptions(device?.id ?? 'none'),
    enabled: device !== null,
    staleTime: 30_000,
    queryFn: ({ signal }) => {
      if (!device) throw new Error('No device selected.');
      return listDeviceExemptions(device.id, signal);
    },
  });

  const create = useMutation({
    mutationFn: () => {
      if (!device) throw new Error('No device selected.');
      return createDeviceExemption(device.id, {
        control_id: controlId.trim(),
        reason: reason.trim(),
        expires_at: expiresAt ? new Date(expiresAt).toISOString() : undefined,
      });
    },
    onSuccess: () => {
      toast.push({
        tone: 'success',
        title: 'Exemption recorded',
        message: 'The control now reports not_applicable on this device, with the reason attached.',
      });
      setControlId('');
      setReason('');
      setExpiresAt('');
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

  async function onRemove(exemption: Exemption) {
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
          <section className="drawer-section">
            <h3 className="drawer-section-title">Record an exemption</h3>
            <div className="form-grid">
              <label className="field">
                <span className="field-label">Control ID</span>
                <input
                  type="text"
                  value={controlId}
                  onChange={(event) => setControlId(event.target.value)}
                  placeholder="e.g. WIN-FW-001"
                />
              </label>
              <label className="field">
                <span className="field-label">Expires at (optional)</span>
                <input
                  type="datetime-local"
                  value={expiresAt}
                  onChange={(event) => setExpiresAt(event.target.value)}
                />
              </label>
              <label className="field span-2">
                <span className="field-label">Reason</span>
                <textarea
                  value={reason}
                  onChange={(event) => setReason(event.target.value)}
                  rows={3}
                  placeholder="Why does this control not apply to this device?"
                />
              </label>
            </div>
            <button
              type="button"
              className="button button-primary"
              onClick={() => create.mutate()}
              disabled={create.isPending || controlId.trim() === '' || reason.trim() === ''}
            >
              {create.isPending ? 'Recording…' : 'Record exemption'}
            </button>
          </section>
        ) : (
          <Notice tone="info" title="Read-only">
            Recording or removing exemptions is an administrator action. You can still review the
            exemptions recorded for this device.
          </Notice>
        )}

        <section className="drawer-section">
          <h3 className="drawer-section-title">Current exemptions</h3>
          {exemptions.isLoading ? <EmptyState title="Loading exemptions…" compact /> : null}
          {exemptions.isError ? (
            <ErrorState
              error={exemptions.error}
              onRetry={() => void exemptions.refetch()}
              scope="Exemptions"
              compact
            />
          ) : null}
          {exemptions.data && exemptions.data.length === 0 ? (
            <EmptyState
              title="No exemptions recorded"
              description="Every control in the baseline is evaluated normally on this device."
              compact
            />
          ) : null}
          {exemptions.data && exemptions.data.length > 0 ? (
            <DataTable
              columns={[
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
                  cell: (row) =>
                    row.expires_at ? (
                      formatDateTime(row.expires_at)
                    ) : (
                      <NeutralBadge label="No expiry" title="This exemption does not expire." />
                    ),
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
                        onClick={() => void onRemove(row)}
                        disabled={remove.isPending}
                      >
                        Remove
                      </button>
                    ) : null,
                },
              ]}
              rows={exemptions.data}
              rowKey={(row) => row.control_id}
              caption="Per-device control exemptions"
              empty={<EmptyState title="No exemptions" compact />}
            />
          ) : null}
        </section>
      </div>
    </Drawer>
  );
}

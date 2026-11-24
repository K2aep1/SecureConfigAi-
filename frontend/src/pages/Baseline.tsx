/**
 * Baseline.
 *
 * Renders the shipped baseline pack in full: every control with its weight,
 * severity, category, rationale, expected state and standard references (each a
 * link, and only when the URL is a safe http(s) target). Nothing here is
 * scan-specific — this is the definition every assessment is measured against.
 */

import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { getBaseline, queryKeys } from '../api';
import { useDocumentTitle } from '../hooks/useAppData';
import { useClientWindow } from '../hooks/useClientWindow';
import { DataTable, LoadMore, type Column } from '../components/DataTable';
import { SeverityBadge } from '../components/Badges';
import { ControlDrawer, controlDetailFromBaseline, type ControlDetail } from '../components/ControlDrawer';
import { MetricCard, MetricGrid } from '../components/MetricCard';
import { JsonFacts } from '../components/JsonFacts';
import { EmptyState, ErrorState, LoadingState, Notice } from '../components/States';
import { formatDate, formatJsonInline, humanize } from '../lib/format';
import { safeExternalHref } from '../lib/url';
import type { BaselineControl, JsonValue } from '../types';

const PAGE_SIZE = 25;

/**
 * In the shipped pack `applicability` is an object of conditions rather than a
 * single word, so both shapes are rendered without assuming one.
 */
function applicabilityText(value: JsonValue): string {
  if (value === null || value === undefined) return '—';
  if (typeof value === 'string') return humanize(value);
  if (typeof value === 'boolean') return value ? 'always' : 'never';
  if (typeof value === 'number') return String(value);
  return formatJsonInline(value, 60);
}

export default function BaselinePage() {
  useDocumentTitle('Baseline · SecureConfigAI');
  const [inspected, setInspected] = useState<ControlDetail | null>(null);
  const [category, setCategory] = useState('');
  const [severity, setSeverity] = useState('');
  const [search, setSearch] = useState('');

  const baseline = useQuery({
    queryKey: queryKeys.policies.baseline(),
    staleTime: 5 * 60 * 1000,
    queryFn: ({ signal }) => getBaseline(signal),
  });

  const controls = useMemo(() => baseline.data?.controls ?? [], [baseline.data]);

  const categories = useMemo(() => {
    const unique = new Set<string>();
    for (const control of controls) if (control.category) unique.add(control.category);
    return Array.from(unique).sort((left, right) => left.localeCompare(right));
  }, [controls]);

  const severities = useMemo(() => {
    const unique = new Set<string>();
    for (const control of controls) if (control.severity) unique.add(String(control.severity));
    return Array.from(unique).sort((left, right) => left.localeCompare(right));
  }, [controls]);

  const filtered = useMemo(() => {
    const needle = search.trim().toLowerCase();
    return controls.filter((control) => {
      if (category && control.category !== category) return false;
      if (severity && String(control.severity) !== severity) return false;
      if (needle) {
        const haystack = `${control.control_id} ${control.title} ${control.category}`.toLowerCase();
        if (!haystack.includes(needle)) return false;
      }
      return true;
    });
  }, [controls, category, severity, search]);

  const windowed = useClientWindow(filtered, PAGE_SIZE);
  const weightTotal = useMemo(
    () => controls.reduce((total, control) => total + (Number(control.weight) || 0), 0),
    [controls],
  );

  const columns: Column<BaselineControl>[] = [
    {
      id: 'control',
      header: 'Control',
      width: '24%',
      cell: (row) => (
        <button
          type="button"
          className="cell-primary"
          onClick={() => setInspected(controlDetailFromBaseline(row))}
        >
          <code className="cell-code">{row.control_id}</code>
          <span className="cell-title">{row.title}</span>
        </button>
      ),
    },
    {
      id: 'category',
      header: 'Category',
      width: '13%',
      cell: (row) => row.category,
    },
    {
      id: 'severity',
      header: 'Severity',
      width: '11%',
      cell: (row) => <SeverityBadge severity={row.severity} />,
    },
    {
      id: 'weight',
      header: 'Weight',
      align: 'right',
      width: '8%',
      cell: (row) => row.weight,
    },
    {
      id: 'expected',
      header: 'Expected state',
      width: '17%',
      cell: (row) => (
        <code className="cell-code" title={formatJsonInline(row.expected_state, 400)}>
          {formatJsonInline(row.expected_state, 40)}
        </code>
      ),
    },
    {
      id: 'collector',
      header: 'Collector',
      hideBelow: 'lg',
      width: '10%',
      cell: (row) =>
        row.collector ? <code className="cell-code">{row.collector}</code> : <span className="muted">—</span>,
    },
    {
      id: 'applicability',
      header: 'Applicability',
      hideBelow: 'lg',
      width: '12%',
      cell: (row) => <span className="muted">{applicabilityText(row.applicability)}</span>,
    },
    {
      id: 'rationale',
      header: 'Rationale',
      hideBelow: 'lg',
      cell: (row) => <span className="cell-subtle">{row.rationale}</span>,
    },
    {
      id: 'references',
      header: 'References',
      width: '15%',
      cell: (row) => {
        const references = row.references ?? [];
        if (references.length === 0) return <span className="muted">—</span>;
        return (
          <span className="ref-inline">
            {references.map((reference, index) => {
              const href = safeExternalHref(reference.url);
              const label = `${reference.standard} ${reference.control}`;
              return href ? (
                <a
                  key={`${reference.standard}-${index}`}
                  href={href}
                  target="_blank"
                  rel="noopener noreferrer"
                  title={reference.url ?? undefined}
                >
                  {label}
                </a>
              ) : (
                <span key={`${reference.standard}-${index}`} title={reference.url ?? undefined}>
                  {label}
                </span>
              );
            })}
          </span>
        );
      },
    },
  ];

  return (
    <div className="page">
      <div className="page-intro">
        <div>
          <span className="eyebrow">Shipped control pack</span>
          <h2>Baseline</h2>
          <p>
            The frozen control definitions every assessment is measured against: weight, severity,
            rationale, expected state and the standards each control maps to.
          </p>
        </div>
      </div>

      {baseline.isLoading ? <LoadingState label="Loading baseline pack…" rows={4} /> : null}

      {baseline.isError ? (
        <ErrorState error={baseline.error} onRetry={() => void baseline.refetch()} scope="Baseline" />
      ) : null}

      {baseline.data ? (
        <>
          <section className="panel">
            <div className="panel-head">
              <div>
                <h2>{baseline.data.title}</h2>
                <p>{baseline.data.description}</p>
              </div>
              <span className="badge badge-outline badge-mono">{baseline.data.baseline_id}</span>
            </div>

            <MetricGrid columns={4}>
              <MetricCard label="Baseline version" value={baseline.data.version} />
              <MetricCard label="Published" value={formatDate(baseline.data.published_at)} />
              <MetricCard
                label="Controls"
                value={baseline.data.control_count ?? controls.length}
              />
              <MetricCard
                label="Total weight"
                value={baseline.data.control_weight_total ?? weightTotal}
                note="Sum of the per-control weights used by the scoring model"
              />
            </MetricGrid>

            {baseline.data.severity_impact ? (
              <div className="baseline-subsection">
                <h3 className="drawer-section-title">Severity impact</h3>
                <div className="count-chip-row">
                  {Object.entries(baseline.data.severity_impact).map(([severity, impact]) => (
                    <span className="count-chip" key={severity}>
                      <span className="count-chip-value">{impact}</span>
                      <span className="count-chip-label">{humanize(severity)}</span>
                    </span>
                  ))}
                </div>
              </div>
            ) : null}

            <div className="baseline-subsection">
              <h3 className="drawer-section-title">Pack references</h3>
              {(() => {
                // Ignore incomplete reference objects rather than rendering
                // literal "undefined · undefined" labels in the UI.
                const references = (baseline.data.references ?? []).filter((reference) => {
                  const standard = String(reference.standard ?? '').trim();
                  const control = String(reference.control ?? '').trim();
                  const url = String(reference.url ?? '').trim();
                  return Boolean(standard || control || url);
                });
                if (references.length === 0) {
                  return <p className="muted">No valid pack-level references recorded.</p>;
                }
                return (
                  <ul className="ref-list">
                    {references.map((reference, index) => {
                      const standard = String(reference.standard ?? '').trim();
                      const control = String(reference.control ?? '').trim();
                      const url = String(reference.url ?? '').trim();
                      const href = safeExternalHref(url);
                      const label = [standard, control].filter(Boolean).join(' · ') || url;
                      return (
                        <li key={`${standard}-${control}-${index}`}>
                          {href ? (
                            <a href={href} target="_blank" rel="noopener noreferrer">
                              {label}
                            </a>
                          ) : (
                            <span>{label}</span>
                          )}
                        </li>
                      );
                    })}
                  </ul>
                );
              })()}
            </div>

            <div className="baseline-subsection">
              <h3 className="drawer-section-title">Thresholds</h3>
              <JsonFacts
                data={baseline.data.thresholds}
                emptyLabel="The pack records no thresholds."
                labelFormatter={(key) => humanize(key)}
              />
            </div>

            <div className="baseline-subsection">
              <h3 className="drawer-section-title">Categories</h3>
              <JsonFacts
                data={baseline.data.categories}
                emptyLabel="The pack records no category metadata."
                labelFormatter={(key) => humanize(key)}
              />
            </div>
          </section>

          {controls.length === 0 ? (
            <Notice tone="warning" title="Empty baseline">
              The baseline pack returned no controls. Assessments would have nothing to evaluate, so
              check the backend's baseline data before trusting any score.
            </Notice>
          ) : null}

          <section className="panel">
            <div className="panel-head">
              <div>
                <h2>Controls in the pack</h2>
                <p>
                  {windowed.visible.length} of {filtered.length} shown
                  {filtered.length !== controls.length ? ` (filtered from ${controls.length})` : ''}
                </p>
              </div>
            </div>

            <div className="filter-grid">
              <label className="field">
                <span className="field-label">Category</span>
                <select value={category} onChange={(event) => setCategory(event.target.value)}>
                  <option value="">Any category</option>
                  {categories.map((value) => (
                    <option key={value} value={value}>
                      {value}
                    </option>
                  ))}
                </select>
              </label>
              <label className="field">
                <span className="field-label">Severity</span>
                <select value={severity} onChange={(event) => setSeverity(event.target.value)}>
                  <option value="">Any severity</option>
                  {severities.map((value) => (
                    <option key={value} value={value}>
                      {humanize(value)}
                    </option>
                  ))}
                </select>
              </label>
              <label className="field">
                <span className="field-label">Search</span>
                <input
                  type="search"
                  value={search}
                  onChange={(event) => setSearch(event.target.value)}
                  placeholder="Control ID, title or category"
                />
              </label>
              <div className="field">
                <span className="field-label">&nbsp;</span>
                <button
                  type="button"
                  className="button button-light"
                  onClick={() => {
                    setCategory('');
                    setSeverity('');
                    setSearch('');
                  }}
                  disabled={category === '' && severity === '' && search === ''}
                >
                  Clear filters
                </button>
              </div>
            </div>

            <DataTable
              columns={columns}
              rows={windowed.visible}
              rowKey={(row) => row.control_id}
              caption="Baseline control definitions"
              empty={
                <EmptyState
                  title="No controls match"
                  description="Clear the filters to see the whole pack."
                  compact
                />
              }
            />
            <LoadMore
              hasMore={windowed.hasMore}
              isLoading={false}
              onLoadMore={windowed.loadMore}
              loadedCount={windowed.visible.length}
              pageSize={PAGE_SIZE}
              unit={`of ${windowed.total} controls`}
            />
          </section>
        </>
      ) : null}

      <ControlDrawer detail={inspected} onClose={() => setInspected(null)} />
    </div>
  );
}

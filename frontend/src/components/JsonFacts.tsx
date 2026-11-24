/**
 * Renders an arbitrary JSON object (contract fields typed as `JsonObject`, e.g.
 * `baseline.thresholds`) as readable rows: scalars become label/value pairs and
 * anything nested is shown as formatted JSON rather than silently dropped.
 */

import { DetailList, DetailRow } from './MetricCard';
import { formatJsonValue, humanize } from '../lib/format';
import type { JsonObject, JsonValue } from '../types';

function isScalar(value: JsonValue): boolean {
  return value === null || typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean';
}

export function JsonFacts({
  data,
  emptyLabel = 'Nothing recorded',
  labelFormatter = humanize,
}: {
  data: JsonObject | null | undefined;
  emptyLabel?: string;
  labelFormatter?: (key: string) => string;
}) {
  const entries = data ? Object.entries(data) : [];
  if (entries.length === 0) return <p className="muted">{emptyLabel}</p>;

  const scalars = entries.filter(([, value]) => isScalar(value));
  const nested = entries.filter(([, value]) => !isScalar(value));

  return (
    <div className="json-facts">
      {scalars.length > 0 ? (
        <DetailList>
          {scalars.map(([key, value]) => (
            <DetailRow
              key={key}
              label={labelFormatter(key)}
              value={value === null ? '—' : typeof value === 'boolean' ? (value ? 'Yes' : 'No') : String(value)}
            />
          ))}
        </DetailList>
      ) : null}
      {nested.map(([key, value]) => (
        <details className="drawer-disclosure" key={key}>
          <summary>{labelFormatter(key)}</summary>
          <pre className="json-block">{formatJsonValue(value)}</pre>
        </details>
      ))}
    </div>
  );
}

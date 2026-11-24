/**
 * Platform security policy (read-only).
 *
 * Renders `GET /admin/security-policy` as readable groups — password, lockout,
 * tokens, rate limits, uploads, headers, retention, secrets, AI — with the
 * `startup_checks` list surfaced first, because a failing startup check explains
 * a lot of otherwise puzzling behaviour elsewhere in the dashboard.
 */

import { useQuery } from '@tanstack/react-query';
import { getSecurityPolicy, queryKeys } from '../api';
import { useDocumentTitle } from '../hooks/useAppData';
import { Badge } from '../components/Badges';
import { DataTable, type Column } from '../components/DataTable';
import { DetailList, DetailRow, MetricCard, MetricGrid } from '../components/MetricCard';
import { EmptyState, ErrorState, LoadingState, Notice } from '../components/States';
import { formatBytes, humanize } from '../lib/format';
import type { RateLimitRule, StartupCheck } from '../types';

function YesNo({ value }: { value: boolean }) {
  return (
    <Badge
      tone={value ? 'ok' : 'warn'}
      label={value ? 'Yes' : 'No'}
      title={value ? 'Enabled' : 'Not enabled'}
    />
  );
}

export default function SecurityPolicyPage() {
  useDocumentTitle('Security policy · SecureConfigAI');

  const policy = useQuery({
    queryKey: queryKeys.admin.securityPolicy(),
    staleTime: 5 * 60 * 1000,
    queryFn: ({ signal }) => getSecurityPolicy(signal),
  });

  const data = policy.data;
  const failingChecks = (data?.startup_checks ?? []).filter((check) => !check.ok);

  const rateLimitColumns: Column<RateLimitRule>[] = [
    { id: 'name', header: 'Rule', cell: (row) => <code className="cell-code">{row.name}</code> },
    { id: 'limit', header: 'Limit', align: 'right', width: '14%', cell: (row) => row.limit },
    {
      id: 'window',
      header: 'Window',
      align: 'right',
      width: '18%',
      cell: (row) => `${row.window_seconds} s`,
    },
    { id: 'scope', header: 'Scope', width: '24%', cell: (row) => humanize(row.scope) },
  ];

  return (
    <div className="page">
      <div className="page-intro">
        <div>
          <span className="eyebrow">Effective configuration</span>
          <h2>Security policy</h2>
          <p>
            The platform's active security settings, read from the running backend. This page is
            read-only: the values come from deployment configuration, not from the dashboard.
          </p>
        </div>
      </div>

      {policy.isLoading ? <LoadingState label="Loading security policy…" rows={4} /> : null}

      {policy.isError ? (
        <ErrorState
          error={policy.error}
          onRetry={() => void policy.refetch()}
          scope="Security policy"
        />
      ) : null}

      {data ? (
        <>
          <section className="panel">
            <div className="panel-head">
              <div>
                <h2>Startup checks</h2>
                <p>
                  Configuration checks run by the backend at start-up. A failing check is a
                  misconfiguration, not a finding about an endpoint.
                </p>
              </div>
              <Badge
                tone={failingChecks.length === 0 ? 'ok' : 'risk'}
                label={
                  failingChecks.length === 0
                    ? `All ${data.startup_checks.length} checks passed`
                    : `${failingChecks.length} of ${data.startup_checks.length} failing`
                }
              />
            </div>

            {data.startup_checks.length === 0 ? (
              <EmptyState title="No startup checks reported" compact />
            ) : (
              <ul className="check-list">
                {data.startup_checks.map((check: StartupCheck) => (
                  <li key={check.name} className={check.ok ? 'check-item check-ok' : 'check-item check-fail'}>
                    <span className="check-mark" aria-hidden="true">
                      {check.ok ? '✓' : '!'}
                    </span>
                    <div className="check-body">
                      <div className="check-head">
                        <strong>{humanize(check.name)}</strong>
                        <Badge
                          tone={check.ok ? 'ok' : check.severity === 'critical' ? 'risk' : 'warn'}
                          label={check.ok ? 'pass' : `${check.severity} · warn`}
                          title={
                            check.ok
                              ? 'This check passed at start-up.'
                              : `This check is failing with severity "${check.severity}".`
                          }
                        />
                      </div>
                      <p className="check-message">{check.message}</p>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </section>

          {failingChecks.length > 0 ? (
            <Notice tone="warning" title="Degraded configuration">
              At least one startup check is failing. Some features (for example AI assistance or token
              security) may behave differently from the documented defaults until this is resolved.
            </Notice>
          ) : null}

          <section className="section-grid">
            <div className="panel">
              <div className="panel-head">
                <div>
                  <h2>Passwords</h2>
                  <p>Applied to registration and password changes.</p>
                </div>
              </div>
              <DetailList>
                <DetailRow label="Minimum length" value={data.password.min_length} />
                <DetailRow label="Maximum length" value={data.password.max_length} />
                <DetailRow label="Letter required" value={<YesNo value={data.password.require_letter} />} />
                <DetailRow label="Digit required" value={<YesNo value={data.password.require_digit} />} />
                <DetailRow label="Symbol required" value={<YesNo value={data.password.require_symbol} />} />
              </DetailList>
            </div>

            <div className="panel">
              <div className="panel-head">
                <div>
                  <h2>Lockout</h2>
                  <p>Brute-force protection on the sign-in route.</p>
                </div>
              </div>
              <DetailList>
                <DetailRow label="Failed attempts before lockout" value={data.lockout.max_failed_logins} />
                <DetailRow label="Lockout duration" value={`${data.lockout.lockout_minutes} minutes`} />
                <DetailRow label="Counting window" value={`${data.lockout.window_minutes} minutes`} />
              </DetailList>
            </div>
          </section>

          <section className="panel">
            <div className="panel-head">
              <div>
                <h2>Tokens</h2>
                <p>Access and refresh token behaviour. Refresh tokens are always sent in the JSON body.</p>
              </div>
            </div>
            <MetricGrid columns={4}>
              <MetricCard label="Algorithm" value={data.tokens.algorithm} />
              <MetricCard
                label="Access token lifetime"
                value={`${data.tokens.access_token_minutes} min`}
                note="Kept in memory only by this client"
              />
              <MetricCard
                label="Refresh token lifetime"
                value={`${data.tokens.refresh_token_days} days`}
                note="Stored in localStorage"
              />
              <MetricCard
                label="Refresh rotation"
                value={<YesNo value={data.tokens.refresh_rotation} />}
                note="Each refresh issues a new refresh token"
              />
              <MetricCard
                label="Reuse detection"
                value={<YesNo value={data.tokens.reuse_detection} />}
                note="Reusing a rotated token revokes the family"
              />
            </MetricGrid>
          </section>

          <section className="panel">
            <div className="panel-head">
              <div>
                <h2>Rate limits</h2>
                <p>Exceeding a limit returns 429 with a Retry-After header, which the UI surfaces.</p>
              </div>
            </div>
            <DataTable
              columns={rateLimitColumns}
              rows={data.rate_limits}
              rowKey={(row) => row.name}
              caption="Rate limit rules"
              empty={<EmptyState title="No rate limits reported" compact />}
            />
          </section>

          <section className="section-grid">
            <div className="panel">
              <div className="panel-head">
                <div>
                  <h2>Uploads</h2>
                  <p>Constraints applied to `POST /scans/upload`.</p>
                </div>
              </div>
              <DetailList>
                <DetailRow label="Maximum size" value={formatBytes(data.uploads.max_bytes)} />
                <DetailRow
                  label="Allowed extensions"
                  value={data.uploads.allowed_extensions.join(', ') || '—'}
                />
                <DetailRow
                  label="Quarantine TTL"
                  value={`${data.uploads.quarantine_ttl_minutes} minutes`}
                />
              </DetailList>
            </div>

            <div className="panel">
              <div className="panel-head">
                <div>
                  <h2>Retention</h2>
                  <p>How long each class of record is kept.</p>
                </div>
              </div>
              <DetailList>
                <DetailRow label="Scans" value={`${data.retention.scan_days} days`} />
                <DetailRow label="Audit entries" value={`${data.retention.audit_days} days`} />
                <DetailRow label="Reports" value={`${data.retention.report_days} days`} />
              </DetailList>
            </div>
          </section>

          <section className="section-grid">
            <div className="panel">
              <div className="panel-head">
                <div>
                  <h2>Response headers</h2>
                  <p>Applied to every API response.</p>
                </div>
              </div>
              <DetailList>
                <DetailRow label="X-Frame-Options" value={data.headers.x_frame_options} />
                <DetailRow label="Referrer-Policy" value={data.headers.referrer_policy} />
                <DetailRow label="HSTS" value={<YesNo value={data.headers.hsts} />} />
              </DetailList>
              <details className="drawer-disclosure">
                <summary>Content-Security-Policy</summary>
                <pre className="json-block">{data.headers.content_security_policy}</pre>
              </details>
            </div>

            <div className="panel">
              <div className="panel-head">
                <div>
                  <h2>Secrets</h2>
                  <p>Presence and strength only — secret values are never returned by the API.</p>
                </div>
              </div>
              <DetailList>
                <DetailRow
                  label="JWT secret configured"
                  value={<YesNo value={data.secrets.jwt_secret_configured} />}
                />
                <DetailRow label="JWT secret strength" value={humanize(data.secrets.jwt_secret_strength)} />
                <DetailRow
                  label="AI key configured"
                  value={<YesNo value={data.secrets.ai_key_configured} />}
                />
              </DetailList>
            </div>
          </section>

          <section className="panel">
            <div className="panel-head">
              <div>
                <h2>AI runtime</h2>
                <p>
                  How the advisory assistant is executed. These limits explain timeouts and cached
                  responses on the AI Assistant page.
                </p>
              </div>
            </div>
            <MetricGrid columns={4}>
              <MetricCard
                label="Enabled"
                value={<YesNo value={data.ai.enabled} />}
                tone={data.ai.enabled ? 'ok' : 'warn'}
              />
              <MetricCard label="Timeout" value={`${data.ai.timeout_seconds} s`} />
              <MetricCard label="Max retries" value={data.ai.max_retries} />
              <MetricCard label="Cache TTL" value={`${data.ai.cache_ttl_minutes} min`} />
              <MetricCard
                label="Redact PII"
                value={<YesNo value={data.ai.redact_pii} />}
                hint="Whether the backend strips personal data before sending evidence to the provider."
              />
            </MetricGrid>
          </section>
        </>
      ) : null}
    </div>
  );
}

/**
 * Global application shell: navigation, API health, global scan action and
 * reproducibility metadata. The shell is responsive; mobile navigation is
 * rendered as an accessible off-canvas panel without changing any routes.
 */

import { useEffect, useState, type ReactNode } from 'react';
import { NavLink, Outlet, useLocation } from 'react-router-dom';
import clsx from 'clsx';
import { NAV_GROUPS, findNavItem, type NavIconName } from './navigation';
import { ScanProgressPanel } from './ScanProgressPanel';
import { ErrorBoundary } from './ErrorBoundary';
import { useHealth, useMeta } from '../hooks/useAppData';
import { useSession } from '../auth/SessionProvider';
import { useScanTracker } from '../state/ScanProvider';
import { formatDate } from '../lib/format';
import { SecureConfigAILogo } from './SecureConfigAILogo';
export function AppShell() {
  const location = useLocation();
  const current = findNavItem(location.pathname);
  const { user, isAdmin, signOut } = useSession();
  const meta = useMeta();
  const health = useHealth();
  const { startScan, isStarting, tracked, isTerminal } = useScanTracker();
  const [mobileNavOpen, setMobileNavOpen] = useState(false);

  const scanBusy = isStarting || (tracked !== null && !isTerminal);
  const displayName = user?.full_name || user?.email || 'Signed in';
  const initials = displayName
    .split(/[\s.@_-]+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase())
    .join('') || 'SC';

  useEffect(() => setMobileNavOpen(false), [location.pathname]);

  useEffect(() => {
    if (!mobileNavOpen) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setMobileNavOpen(false);
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [mobileNavOpen]);

  return (
    <div className={clsx('app-shell', mobileNavOpen && 'app-shell-nav-open')}>
      <a className="skip-link" href="#main-content">Skip to main content</a>

      <aside className={clsx('sidebar', mobileNavOpen && 'sidebar-open')} aria-label="Application navigation">
        <div className="brand brand--secure">
          <SecureConfigAILogo
            tone="dark"
            size="md"
            subtitle="Endpoint security platform"
          />
          <span className="brand-version">2.0</span>
        </div>

        <div className="sidebar-workspace">
          <span className="workspace-indicator" aria-hidden="true" />
          <span><strong>Local workspace</strong><small>Windows endpoint</small></span>
        </div>

        <nav id="primary-navigation" className="nav" aria-label="Primary">
          {NAV_GROUPS.map((group) => {
            const items = group.items.filter((item) => !item.adminOnly || isAdmin);
            if (items.length === 0) return null;
            return (
              <div className="nav-group" key={group.label}>
                <span className="nav-label">{group.label}</span>
                {items.map((item) => (
                  <NavLink
                    key={item.path}
                    to={item.path}
                    end={item.path === '/' || item.path === '/admin'}
                    title={item.hint}
                    onClick={() => setMobileNavOpen(false)}
                    className={({ isActive }) => clsx('nav-item', isActive && 'active')}
                  >
                    <span className="nav-item-icon" aria-hidden="true"><NavGlyph name={item.icon} /></span>
                    <span className="nav-item-copy">
                      <span className="nav-item-title">{item.label}</span>
                      <small>{item.hint}</small>
                    </span>
                    <span className="nav-item-chevron" aria-hidden="true">›</span>
                  </NavLink>
                ))}
              </div>
            );
          })}
        </nav>

        <div className="sidebar-bottom">
          <div className="sidebar-security-note">
            <span className="security-note-icon" aria-hidden="true"><NavGlyph name="shield" /></span>
            <span><strong>Evidence-led security</strong><small>Scoring stays deterministic</small></span>
          </div>
          <div className="sidebar-footer">
            <div className="user-mini">
              <span className="user-avatar" aria-hidden="true">{initials}</span>
              <span className="user-mini-copy">
                <strong title={user?.email ?? undefined}>{displayName}</strong>
                <small>{user?.role ?? 'user'}</small>
              </span>
            </div>
            <button type="button" className="button button-sidebar-signout" onClick={() => void signOut()}>
              <LogoutGlyph />
              <span>Sign out</span>
            </button>
          </div>
        </div>
      </aside>

      <button
        type="button"
        className="sidebar-scrim"
        onClick={() => setMobileNavOpen(false)}
        aria-label="Close navigation"
        tabIndex={mobileNavOpen ? 0 : -1}
      />

      <div className="main">
        <header className="topbar">
          <div className="topbar-leading">
            <button
              type="button"
              className="mobile-nav-toggle"
              onClick={() => setMobileNavOpen((open) => !open)}
              aria-label={mobileNavOpen ? 'Close navigation' : 'Open navigation'}
              aria-expanded={mobileNavOpen}
              aria-controls="primary-navigation"
            >
              <MenuGlyph />
            </button>
            <div className="topbar-title-mark" aria-hidden="true"><NavGlyph name={current?.icon ?? 'overview'} /></div>
            <div className="topbar-titles">
              <span className="eyebrow">{current?.hint ?? 'Security operations'}</span>
              <h1>{current?.label ?? 'SecureConfigAI'}</h1>
            </div>
          </div>

          <div className="top-actions">
            <ConnectivityIndicator
              status={health.status}
              service={health.data?.service}
              environment={health.data?.environment}
            />
            <button
              type="button"
              className="button button-primary topbar-scan-button"
              onClick={() => void startScan()}
              disabled={scanBusy}
            >
              <ScanGlyph />
              <span>{isStarting ? 'Queueing…' : tracked && !isTerminal ? 'Scan running…' : 'Start security scan'}</span>
            </button>
          </div>
        </header>

        <ScanProgressPanel />

        <main className="content" id="main-content">
          <ErrorBoundary scope={current?.label}>
            <Outlet />
          </ErrorBoundary>
        </main>

        <footer className="footer-meta">
          <div className="footer-meta-brand"><span className="footer-brand-dot" /> SecureConfigAI <span className="footer-meta-separator">·</span> Evidence-led endpoint assessment</div>
          <div className="footer-meta-group">
            <span>Scoring model <strong>{meta.data?.scoring_model_version ?? '—'}</strong></span>
            <span>Baseline <strong>{meta.data?.baseline.version ?? '—'}{meta.data?.baseline.title ? ` · ${meta.data.baseline.title}` : ''}</strong></span>
            <span>Controls <strong>{meta.data?.control_count ?? '—'}</strong> · weight <strong>{meta.data?.control_weight_total ?? '—'}</strong></span>
            {meta.data?.baseline.published_at ? <span>Baseline published {formatDate(meta.data.baseline.published_at)}</span> : null}
            <span>App version {meta.data?.app_version ?? '—'}</span>
            {meta.isError ? <span className="footer-meta-warning" title="GET /api/v1/meta did not answer">Version metadata unavailable</span> : null}
          </div>
        </footer>
      </div>
    </div>
  );
}

function ConnectivityIndicator({
  status,
  service,
  environment,
}: {
  status: 'pending' | 'error' | 'success';
  service?: string;
  environment?: string;
}) {
  const label = status === 'success'
    ? `${service ?? 'API'} connected`
    : status === 'pending'
      ? 'Checking API…'
      : 'API unreachable';

  return (
    <span
      className={clsx('connection', `connection-${status === 'success' ? 'ok' : status === 'error' ? 'error' : 'pending'}`)}
      title={status === 'success'
        ? `GET /health answered. Environment: ${environment ?? 'unknown'}.`
        : status === 'error'
          ? 'GET /health did not answer. The backend may not be running.'
          : 'Contacting the API.'}
      role="status"
    >
      <i aria-hidden="true" />
      <span>{label}</span>
    </span>
  );
}

function MenuGlyph() {
  return <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round"><path d="M4 7h16M4 12h16M4 17h16" /></svg>;
}

function ScanGlyph() {
  return <svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="M4 7V4h3M17 4h3v3M20 17v3h-3M7 20H4v-3"/><path d="M4 12h16M8 9l-2 3 2 3M16 9l2 3-2 3"/></svg>;
}

function LogoutGlyph() {
  return <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="M10 4H5a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h5"/><path d="M14 8l4 4-4 4M18 12H9"/></svg>;
}

function NavGlyph({ name }: { name: NavIconName }): ReactNode {
  const common = { width: 19, height: 19, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', strokeWidth: 1.7, strokeLinecap: 'round' as const, strokeLinejoin: 'round' as const, 'aria-hidden': true as const };
  const paths: Record<NavIconName, ReactNode> = {
    overview: <><rect x="3.5" y="3.5" width="7" height="7" rx="1.7"/><rect x="13.5" y="3.5" width="7" height="4.5" rx="1.7"/><rect x="13.5" y="10.5" width="7" height="10" rx="1.7"/><rect x="3.5" y="13.5" width="7" height="7" rx="1.7"/></>,
    scans: <><circle cx="10.8" cy="10.8" r="6.8"/><path d="m16 16 4.5 4.5M8 10.8h5.6M10.8 8v5.6"/></>,
    devices: <><rect x="3" y="4" width="18" height="12.5" rx="2"/><path d="M8 20h8M12 16.5V20M8 9h8M8 12h5"/></>,
    controls: <><rect x="4" y="3.5" width="16" height="17" rx="2"/><path d="m7.5 9 1.6 1.6L12 7.7M14.5 9h2.5M7.5 15l1.6 1.6 2.9-2.9M14.5 15h2.5"/></>,
    policies: <><path d="M12 3.5 20 7v5.5c0 4.1-2.5 6.9-8 8.8-5.5-1.9-8-4.7-8-8.8V7l8-3.5Z"/><path d="m8.5 12.3 2.2 2.2 4.8-5"/></>,
    baseline: <><path d="M4 5.5h16M4 12h16M4 18.5h16"/><circle cx="8" cy="5.5" r="1.6" fill="currentColor"/><circle cx="15.5" cy="12" r="1.6" fill="currentColor"/><circle cx="11" cy="18.5" r="1.6" fill="currentColor"/></>,
    reports: <><path d="M6 3.5h8l4 4v13H6a2 2 0 0 1-2-2v-13a2 2 0 0 1 2-2Z"/><path d="M14 3.5v4h4M8 12h8M8 15.5h8M8 8.8h2"/></>,
    ai: <><path d="M12 3.5 13.9 9l5.6 1.9-5.6 1.9L12 18.5l-1.9-5.7-5.6-1.9L10.1 9 12 3.5Z"/><path d="m19 15 .9 2.1L22 18l-2.1.9L19 21l-.9-2.1L16 18l2.1-.9L19 15Z"/></>,
    admin: <><circle cx="12" cy="8" r="3.3"/><path d="M5 20v-1.5a4.5 4.5 0 0 1 4.5-4.5h5a4.5 4.5 0 0 1 4.5 4.5V20M18.5 4.5a3.4 3.4 0 0 1 0 6.5"/></>,
    shield: <><path d="M12 3.5 20 7v5.5c0 4.1-2.5 6.9-8 8.8-5.5-1.9-8-4.7-8-8.8V7l8-3.5Z"/><path d="M12 8v4M12 15.5h.01"/></>,
  };
  return <svg {...common}>{paths[name]}</svg>;
}

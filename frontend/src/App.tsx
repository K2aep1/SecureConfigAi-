/**
 * Routing only.
 *
 * Every page is a lazily-loaded chunk wrapped in its own `Suspense` boundary
 * with a visible loading state, so navigating to a heavy page never blocks the
 * shell and never shows a blank screen. Session and role gating live in
 * `src/auth/`.
 */

import { Suspense, lazy, type ReactNode } from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';
import { AppShell } from './components/AppShell';
import { PageLoading } from './components/PageLoading';
import { RequireAuth, RequireRole } from './auth/RequireAuth';

const SignInPage = lazy(() => import('./pages/SignIn'));
const OverviewPage = lazy(() => import('./pages/Overview'));
const ScansPage = lazy(() => import('./pages/Scans'));
const ScanDetailPage = lazy(() => import('./pages/ScanDetail'));
const DevicesPage = lazy(() => import('./pages/Devices'));
const ControlsPage = lazy(() => import('./pages/Controls'));
const PoliciesPage = lazy(() => import('./pages/Policies'));
const BaselinePage = lazy(() => import('./pages/Baseline'));
const ReportsPage = lazy(() => import('./pages/Reports'));
const AiAssistantPage = lazy(() => import('./pages/AiAssistant'));
const AdminPage = lazy(() => import('./pages/Admin'));
const SecurityPolicyPage = lazy(() => import('./pages/SecurityPolicy'));
const NotFoundPage = lazy(() => import('./pages/NotFound'));

/** Route-level code splitting: each page loads on demand, with a real fallback. */
function route(node: ReactNode, title: string): ReactNode {
  return (
    <Suspense fallback={<PageLoading title={title} hint="Loading this view's code." />}>
      {node}
    </Suspense>
  );
}

export default function App() {
  return (
    <Routes>
      <Route path="/signin" element={route(<SignInPage />, 'Sign-in')} />

      {/* Everything below requires an authenticated session. */}
      <Route element={<RequireAuth />}>
        <Route element={<AppShell />}>
          <Route index element={route(<OverviewPage />, 'Overview')} />
          <Route path="scans" element={route(<ScansPage />, 'Scans')} />
          <Route path="scans/:id" element={route(<ScanDetailPage />, 'Scan detail')} />
          <Route path="devices" element={route(<DevicesPage />, 'Devices')} />
          <Route path="controls" element={route(<ControlsPage />, 'Controls')} />
          <Route path="policies" element={route(<PoliciesPage />, 'Policies')} />
          <Route path="baseline" element={route(<BaselinePage />, 'Baseline')} />
          <Route path="reports" element={route(<ReportsPage />, 'Reports')} />
          <Route path="ai" element={route(<AiAssistantPage />, 'AI Assistant')} />

          {/* Administrator-only surfaces; the API enforces this as well. */}
          <Route element={<RequireRole role="admin" />}>
            <Route path="admin" element={route(<AdminPage />, 'Administration')} />
            <Route
              path="admin/security-policy"
              element={route(<SecurityPolicyPage />, 'Security policy')}
            />
          </Route>

          <Route path="*" element={route(<NotFoundPage />, 'Not found')} />
        </Route>
      </Route>

      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

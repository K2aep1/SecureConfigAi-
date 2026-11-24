/**
 * Protected routes.
 *
 * `RequireAuth` guards every authenticated page and remembers where the user was
 * heading, so a forced sign-out or an expired session returns them there after
 * signing in. `RequireRole` layers administrator-only access on top: the API is
 * still the authority (it answers `403`), but the UI does not present controls
 * the user cannot use.
 */

import { Navigate, Outlet, useLocation } from 'react-router-dom';
import { useSession } from './SessionProvider';
import { SessionLoading } from '../components/PageLoading';
import { EmptyState } from '../components/States';
import type { UserRole } from '../types';

export function RequireAuth() {
  const { status } = useSession();
  const location = useLocation();

  if (status === 'loading') return <SessionLoading />;
  if (status === 'anonymous') {
    return (
      <Navigate
        to="/signin"
        replace
        state={{ from: `${location.pathname}${location.search}` }}
      />
    );
  }
  return <Outlet />;
}

export function RequireRole({ role }: { role: UserRole }) {
  const { user } = useSession();

  if (user?.role !== role) {
    return (
      <EmptyState
        title="Administrator access required"
        description={`This area is restricted to accounts with the "${role}" role. Ask an administrator if you need access — the API will also refuse these requests with a 403.`}
      />
    );
  }
  return <Outlet />;
}

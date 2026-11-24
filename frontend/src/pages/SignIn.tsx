/**
 * Sign-in / registration.
 *
 * Password rules come from `GET /auth/policy` (unauthenticated), so the form
 * states the real policy instead of a hard-coded guess. Lockout (`423`) and
 * disabled-account (`403`) responses are surfaced as their own titles by
 * `presentError`, because "wrong password" and "account locked" need different
 * user actions.
 */

import { useState, type FormEvent } from 'react';
import { Navigate, useLocation, useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { getAuthPolicy, queryKeys } from '../api';
import { useSession } from '../auth/SessionProvider';
import { useDocumentTitle } from '../hooks/useAppData';
import { Notice } from '../components/States';
import { presentError } from '../lib/errors';
import type { PasswordRules } from '../types';

interface LocationState {
  from?: string;
}

function passwordChecks(password: string, rules: PasswordRules | undefined) {
  return [
    {
      label: rules ? `At least ${rules.min_length} characters` : 'At least 12 characters',
      ok: rules ? password.length >= rules.min_length : password.length >= 12,
    },
    {
      label: rules ? `At most ${rules.max_length} characters` : 'At most 72 characters',
      ok: rules ? password.length <= rules.max_length : password.length <= 72,
    },
    {
      label: 'Contains a letter',
      ok: rules?.require_letter === false ? true : /[A-Za-z]/.test(password),
    },
    {
      label: 'Contains a digit',
      ok: rules?.require_digit === false ? true : /\d/.test(password),
    },
    {
      label: 'Contains a symbol',
      ok: rules?.require_symbol ? /[^A-Za-z0-9]/.test(password) : true,
      optional: rules?.require_symbol !== true,
    },
  ];
}

export default function SignInPage() {
  useDocumentTitle('Sign in · SecureConfigAI');
  const { status, signIn, register } = useSession();
  const navigate = useNavigate();
  const location = useLocation();
  const redirectTo = (location.state as LocationState | null)?.from ?? '/';

  const [mode, setMode] = useState<'signin' | 'register'>('signin');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [fullName, setFullName] = useState('');
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  const policy = useQuery({
    queryKey: queryKeys.auth.policy(),
    queryFn: ({ signal }) => getAuthPolicy(signal),
    staleTime: 30 * 60 * 1000,
    retry: 1,
  });

  if (status === 'authenticated') return <Navigate to={redirectTo} replace />;

  const checks = passwordChecks(password, policy.data?.password);
  const passwordValid = checks.every((check) => check.ok);
  const presentation = error ? presentError(error) : null;

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      if (mode === 'register') {
        if (!passwordValid) {
          throw new Error('The password does not meet the policy shown below.');
        }
        await register(email, password, fullName);
      } else {
        await signIn(email, password);
      }
      navigate(redirectTo, { replace: true });
    } catch (caught) {
      setError(caught);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="auth-shell">
      <div className="auth-panel">
        <div className="brand auth-brand">
          <span className="brand-mark" aria-hidden="true">
            S
          </span>
          <div>
            <strong>SecureConfigAI</strong>
            <span>Windows security configuration assessment</span>
          </div>
        </div>

        <h1 className="auth-title">{mode === 'signin' ? 'Sign in' : 'Create account'}</h1>
        <p className="auth-subtitle">
          Deterministic control assessment from real endpoint evidence, with an audit trail behind
          every action.
        </p>

        {presentation ? (
          <Notice tone="error" title={presentation.title}>
            {presentation.message}
            {presentation.status === 423 && policy.data
              ? ` Accounts lock after ${policy.data.max_failed_logins} failed attempts for ${policy.data.lockout_minutes} minutes.`
              : ''}
          </Notice>
        ) : null}

        <form className="auth-form" onSubmit={onSubmit}>
          {mode === 'register' ? (
            <label className="field">
              <span className="field-label">Full name (optional)</span>
              <input
                type="text"
                name="full_name"
                value={fullName}
                onChange={(event) => setFullName(event.target.value)}
                autoComplete="name"
              />
            </label>
          ) : null}

          <label className="field">
            <span className="field-label">Email address</span>
            <input
              type="email"
              name="email"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              autoComplete="username"
              required
            />
          </label>

          <label className="field">
            <span className="field-label">Password</span>
            <input
              type="password"
              name="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              autoComplete={mode === 'signin' ? 'current-password' : 'new-password'}
              required
            />
          </label>

          {mode === 'register' ? (
            <ul className="rule-list">
              {checks.map((check) => (
                <li key={check.label} className={check.ok ? 'rule-ok' : 'rule-pending'}>
                  <span aria-hidden="true">{check.ok ? '✓' : '·'}</span>
                  <span>
                    {check.label}
                    {check.optional ? ' (optional)' : ''}
                  </span>
                </li>
              ))}
            </ul>
          ) : null}

          <button type="submit" className="button button-primary full" disabled={busy}>
            {busy ? 'Please wait…' : mode === 'signin' ? 'Sign in' : 'Create account and sign in'}
          </button>
        </form>

        <button
          type="button"
          className="link-button"
          onClick={() => {
            setMode(mode === 'signin' ? 'register' : 'signin');
            setError(null);
          }}
        >
          {mode === 'signin' ? 'Need an account? Register' : 'Already registered? Sign in'}
        </button>

        <div className="auth-footnote">
          {policy.data ? (
            <span>
              Sessions last {policy.data.access_token_minutes} min per access token and{' '}
              {policy.data.refresh_token_days} days per refresh token.
            </span>
          ) : (
            <span>Session policy unavailable — the API did not answer `GET /auth/policy`.</span>
          )}
        </div>
      </div>
    </div>
  );
}

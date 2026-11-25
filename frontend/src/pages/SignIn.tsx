/**
 * Sign-in / registration.
 *
 * Password rules come from GET /auth/policy (unauthenticated).
 * Registration is disabled until the server policy is available.
 *
 * Redirect destinations are restricted to same-application paths.
 * Lockout (423) and disabled-account (403) responses are presented
 * through presentError with distinct titles and messages.
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

interface PasswordCheck {
  label: string;
  ok: boolean;
  optional?: boolean;
}

/**
 * Accept only relative paths belonging to this application.
 * Reject external URLs, protocol-relative URLs and malformed targets.
 */
function safeRedirect(target: unknown): string {
  if (
    typeof target !== 'string' ||
    !target.startsWith('/') ||
    target.startsWith('//') ||
    target.includes('\\')
  ) {
    return '/';
  }

  try {
    const url = new URL(target, window.location.origin);

    if (url.origin !== window.location.origin) {
      return '/';
    }

    return `${url.pathname}${url.search}${url.hash}`;
  } catch {
    return '/';
  }
}

/**
 * Build password checks exclusively from the server-provided policy.
 * No guessed fallback requirements are displayed or enforced.
 */
function passwordChecks(
  password: string,
  rules: PasswordRules | undefined,
): PasswordCheck[] {
  if (!rules) {
    return [];
  }

  return [
    {
      label: `At least ${rules.min_length} characters`,
      ok: password.length >= rules.min_length,
    },
    {
      label: `At most ${rules.max_length} characters`,
      ok: password.length <= rules.max_length,
    },
    {
      label: 'Contains a letter',
      ok: rules.require_letter === false || /[A-Za-z]/.test(password),
    },
    {
      label: 'Contains a digit',
      ok: rules.require_digit === false || /\d/.test(password),
    },
    {
      label: 'Contains a symbol',
      ok: !rules.require_symbol || /[^A-Za-z0-9]/.test(password),
      optional: !rules.require_symbol,
    },
  ];
}

export default function SignInPage() {
  useDocumentTitle('Sign in · SecureConfigAI');

  const { status, signIn, register } = useSession();
  const navigate = useNavigate();
  const location = useLocation();

  const locationState = location.state as LocationState | null;
  const redirectTo = safeRedirect(locationState?.from);

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

  const passwordRules = policy.data?.password;
  const checks = passwordChecks(password, passwordRules);

  const passwordValid =
    Boolean(passwordRules) &&
    checks.length > 0 &&
    checks.every((check) => check.ok);

  const presentation = error ? presentError(error) : null;

  /**
   * Do not render the authentication form for an authenticated session.
   */
  if (status === 'authenticated') {
    return <Navigate to={redirectTo} replace />;
  }

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    if (busy) {
      return;
    }

    setError(null);

    const normalizedEmail = email.trim();
    const normalizedFullName = fullName.trim();

    if (!normalizedEmail) {
      setError(new Error('Please enter your email address.'));
      return;
    }

    if (mode === 'register') {
      if (!passwordRules) {
        setError(
          new Error(
            'Registration is temporarily unavailable because the password policy could not be loaded.',
          ),
        );
        return;
      }

      if (!passwordValid) {
        setError(
          new Error('The password does not meet the server password policy.'),
        );
        return;
      }
    }

    setBusy(true);

    try {
      if (mode === 'register') {
        await register(normalizedEmail, password, normalizedFullName);
      } else {
        await signIn(normalizedEmail, password);
      }

      navigate(redirectTo, { replace: true });
    } catch (caught) {
      setError(caught);
    } finally {
      setBusy(false);
    }
  }

  function toggleMode() {
    setMode((current) =>
      current === 'signin' ? 'register' : 'signin',
    );

    setPassword('');
    setFullName('');
    setError(null);
  }

  const registrationUnavailable =
    mode === 'register' && (!passwordRules || policy.isLoading || policy.isError);

  const submitDisabled =
    busy ||
    registrationUnavailable ||
    (mode === 'register' && !passwordValid);

  return (
    <div className="auth-shell">
      <div className="auth-panel">
        {/* Brand */}
        <div className="brand auth-brand">
          <span className="brand-mark" aria-hidden="true">
            S
          </span>

          <div>
            <strong>SecureConfigAI</strong>
            <span>Windows security configuration assessment</span>
          </div>
        </div>

        {/* Heading */}
        <h1 className="auth-title">
          {mode === 'signin' ? 'Sign in' : 'Create account'}
        </h1>

        <p className="auth-subtitle">
          Deterministic control assessment from real endpoint evidence, with an
          audit trail behind every action.
        </p>

        {/* Authentication error */}
        {presentation ? (
          <div role="alert" aria-live="assertive">
            <Notice tone="error" title={presentation.title}>
              {presentation.message}

              {presentation.status === 423 && policy.data ? (
                <>
                  {' '}
                  Accounts lock after {policy.data.max_failed_logins} failed
                  attempts for {policy.data.lockout_minutes} minutes.
                </>
              ) : null}
            </Notice>
          </div>
        ) : null}

        {/* Authentication form */}
        <form className="auth-form" onSubmit={onSubmit}>
          {/* Full name */}
          {mode === 'register' ? (
            <label className="field">
              <span className="field-label">Full name (optional)</span>

              <input
                type="text"
                name="full_name"
                value={fullName}
                onChange={(event) => setFullName(event.target.value)}
                autoComplete="name"
                disabled={busy}
              />
            </label>
          ) : null}

          {/* Email */}
          <label className="field">
            <span className="field-label">Email address</span>

            <input
              type="email"
              name="email"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              autoComplete="username"
              autoCapitalize="none"
              spellCheck={false}
              required
              disabled={busy}
            />
          </label>

          {/* Password */}
          <label className="field">
            <span className="field-label">Password</span>

            <input
              type="password"
              name="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              autoComplete={
                mode === 'signin' ? 'current-password' : 'new-password'
              }
              aria-describedby={
                mode === 'register' ? 'password-rules' : undefined
              }
              required
              disabled={busy}
            />
          </label>

          {/* Server-provided password rules */}
          {mode === 'register' ? (
            <div>
              {policy.isLoading ? (
                <p className="auth-footnote" role="status">
                  Loading password requirements…
                </p>
              ) : policy.isError || !passwordRules ? (
                <Notice tone="error" title="Password policy unavailable">
                  Registration is temporarily disabled because the server
                  password policy could not be retrieved. Please try again
                  later.
                </Notice>
              ) : (
                <ul className="rule-list" id="password-rules">
                  {checks.map((check) => (
                    <li
                      key={check.label}
                      className={check.ok ? 'rule-ok' : 'rule-pending'}
                    >
                      <span aria-hidden="true">
                        {check.ok ? '✓' : '·'}
                      </span>

                      <span>
                        {check.label}
                        {check.optional ? ' (optional)' : ''}
                      </span>

                      <span className="sr-only">
                        {check.ok ? 'Requirement met' : 'Requirement not met'}
                      </span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          ) : null}

          {/* Submit */}
          <button
            type="submit"
            className="button button-primary full"
            disabled={submitDisabled}
          >
            {busy
              ? 'Please wait…'
              : mode === 'signin'
                ? 'Sign in'
                : 'Create account and sign in'}
          </button>
        </form>

        {/* Mode switch */}
        <button
          type="button"
          className="link-button"
          onClick={toggleMode}
          disabled={busy}
        >
          {mode === 'signin'
            ? 'Need an account? Register'
            : 'Already registered? Sign in'}
        </button>

        {/* Authentication policy information */}
        <div className="auth-footnote" aria-live="polite">
          {policy.isLoading ? (
            <span>Loading authentication policy…</span>
          ) : policy.isError || !policy.data ? (
            <span>
              Authentication policy unavailable. Some authentication
              information cannot currently be displayed.
            </span>
          ) : (
            <span>
              Sessions last {policy.data.access_token_minutes} min per access
              token and {policy.data.refresh_token_days} days per refresh
              token.
            </span>
          )}
        </div>
      </div>
    </div>
  );
}
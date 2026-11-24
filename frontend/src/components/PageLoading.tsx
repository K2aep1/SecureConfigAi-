/**
 * Route-level loading state.
 *
 * Used as the `Suspense` fallback for lazily-loaded route chunks and while the
 * session is being restored. It is deliberately visible and informative: a
 * short delay while a chunk downloads should look intentional, never frozen.
 */

export function PageLoading({
  title = 'Loading view',
  hint = 'Fetching the code for this page.',
}: {
  title?: string;
  hint?: string;
}) {
  return (
    <div className="page-loading" role="status" aria-live="polite">
      <span className="spinner spinner-large" aria-hidden="true" />
      <div>
        <p className="page-loading-title">{title}</p>
        <p className="page-loading-hint">{hint}</p>
      </div>
    </div>
  );
}

/** Full-window variant used before the shell exists (session restore). */
export function SessionLoading() {
  return (
    <div className="session-loading">
      <div className="brand brand-stacked">
        <span className="brand-mark" aria-hidden="true">
          S
        </span>
        <div>
          <strong>SecureConfigAI</strong>
          <span>Windows security configuration assessment</span>
        </div>
      </div>
      <PageLoading title="Restoring session" hint="Exchanging the stored refresh token for a new access token." />
    </div>
  );
}

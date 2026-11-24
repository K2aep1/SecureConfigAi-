/**
 * Error boundary.
 *
 * Catches render-time failures anywhere below it so a single bad payload cannot
 * white-screen the dashboard. Route-level children are wrapped individually, so
 * a crash in one page leaves the shell (navigation, scan tracker) usable.
 */

import { Component, type ErrorInfo, type ReactNode } from 'react';

interface ErrorBoundaryProps {
  children: ReactNode;
  /** Optional label shown in the fallback, e.g. the page name. */
  scope?: string;
  /** Custom fallback; receives the captured error and a reset callback. */
  fallback?: (error: Error, reset: () => void) => ReactNode;
}

interface ErrorBoundaryState {
  error: Error | null;
}

export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  state: ErrorBoundaryState = { error: null };

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    // Keep the technical detail in the console; the UI stays calm and readable.
    console.error('[SecureConfigAI] Unhandled UI error', error, info.componentStack);
  }

  private reset = (): void => {
    this.setState({ error: null });
  };

  render(): ReactNode {
    const { error } = this.state;
    if (!error) return this.props.children;

    if (this.props.fallback) return this.props.fallback(error, this.reset);

    return (
      <div className="error-boundary" role="alert">
        <div className="error-boundary-mark" aria-hidden="true">
          !
        </div>
        <div>
          <h2 className="error-boundary-title">
            {this.props.scope ? `${this.props.scope} stopped rendering` : 'This view stopped rendering'}
          </h2>
          <p className="error-boundary-text">
            The rest of the dashboard is still available. Retry the view, or reload the page if the
            problem persists.
          </p>
          <pre className="error-boundary-detail">{error.message}</pre>
          <div className="inline-actions">
            <button type="button" className="button button-primary" onClick={this.reset}>
              Retry this view
            </button>
            <button
              type="button"
              className="button button-light"
              onClick={() => window.location.reload()}
            >
              Reload page
            </button>
          </div>
        </div>
      </div>
    );
  }
}

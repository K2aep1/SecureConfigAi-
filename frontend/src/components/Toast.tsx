/**
 * Toast system.
 *
 * A single provider owns the queue; `useToast()` exposes imperative helpers.
 * The region is `aria-live="polite"` so screen readers announce feedback without
 * stealing focus, and every toast is dismissible from the keyboard.
 */

import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react';
import clsx from 'clsx';

export type ToastTone = 'info' | 'success' | 'warning' | 'error';

export interface Toast {
  id: string;
  tone: ToastTone;
  title: string;
  message?: string;
  /** Milliseconds; `0` keeps the toast until dismissed. */
  durationMs: number;
}

export interface ToastInput {
  tone?: ToastTone;
  title: string;
  message?: string;
  durationMs?: number;
}

interface ToastContextValue {
  toasts: Toast[];
  push: (input: ToastInput) => string;
  dismiss: (id: string) => void;
  clear: () => void;
}

const ToastContext = createContext<ToastContextValue | null>(null);

const DEFAULT_DURATION: Record<ToastTone, number> = {
  info: 6000,
  success: 6000,
  warning: 9000,
  error: 12000,
};

let toastSequence = 0;

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const timers = useRef(new Map<string, number>());

  const dismiss = useCallback((id: string) => {
    const timer = timers.current.get(id);
    if (timer !== undefined) {
      window.clearTimeout(timer);
      timers.current.delete(id);
    }
    setToasts((current) => current.filter((toast) => toast.id !== id));
  }, []);

  const push = useCallback(
    (input: ToastInput): string => {
      toastSequence += 1;
      const id = `toast-${toastSequence}`;
      const tone = input.tone ?? 'info';
      const toast: Toast = {
        id,
        tone,
        title: input.title,
        message: input.message,
        durationMs: input.durationMs ?? DEFAULT_DURATION[tone],
      };
      // Keep the queue short so the page is never buried in notifications.
      setToasts((current) => [...current.slice(-3), toast]);
      if (toast.durationMs > 0) {
        const timer = window.setTimeout(() => dismiss(id), toast.durationMs);
        timers.current.set(id, timer);
      }
      return id;
    },
    [dismiss],
  );

  const clear = useCallback(() => {
    for (const timer of timers.current.values()) window.clearTimeout(timer);
    timers.current.clear();
    setToasts([]);
  }, []);

  const value = useMemo<ToastContextValue>(
    () => ({ toasts, push, dismiss, clear }),
    [toasts, push, dismiss, clear],
  );

  return (
    <ToastContext.Provider value={value}>
      {children}
      <ToastRegion toasts={toasts} onDismiss={dismiss} />
    </ToastContext.Provider>
  );
}

export function useToast(): ToastContextValue {
  const context = useContext(ToastContext);
  if (!context) {
    throw new Error('useToast must be used inside <ToastProvider>.');
  }
  return context;
}

function ToastRegion({ toasts, onDismiss }: { toasts: Toast[]; onDismiss: (id: string) => void }) {
  return (
    <div className="toast-region" role="region" aria-label="Notifications">
      <div aria-live="polite" aria-atomic="false" className="toast-stack">
        {toasts.map((toast) => (
          <div key={toast.id} className={clsx('toast', `toast-${toast.tone}`)}>
            <div className="toast-body">
              <strong className="toast-title">{toast.title}</strong>
              {toast.message ? <p className="toast-message">{toast.message}</p> : null}
            </div>
            <button
              type="button"
              className="toast-dismiss"
              onClick={() => onDismiss(toast.id)}
              aria-label={`Dismiss notification: ${toast.title}`}
            >
              <span aria-hidden="true">×</span>
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}

/**
 * Confirmation dialog.
 *
 * Replaces `window.confirm`, which is unstyleable, unstyled by the design
 * system, and blocks the whole page. Destructive actions (delete scan, delete
 * policy, remove device, disable a user) all route through this.
 */

import { createContext, useCallback, useContext, useMemo, useRef, useState, type ReactNode } from 'react';
import { Drawer } from './Drawer';

export interface ConfirmOptions {
  title: string;
  message: ReactNode;
  confirmLabel?: string;
  cancelLabel?: string;
  destructive?: boolean;
}

interface ConfirmContextValue {
  confirm: (options: ConfirmOptions) => Promise<boolean>;
}

const ConfirmContext = createContext<ConfirmContextValue | null>(null);

interface PendingConfirm {
  options: ConfirmOptions;
  resolve: (value: boolean) => void;
}

export function ConfirmProvider({ children }: { children: ReactNode }) {
  const [pending, setPending] = useState<PendingConfirm | null>(null);
  const pendingRef = useRef<PendingConfirm | null>(null);

  const confirm = useCallback((options: ConfirmOptions) => {
    return new Promise<boolean>((resolve) => {
      const next: PendingConfirm = { options, resolve };
      pendingRef.current = next;
      setPending(next);
    });
  }, []);

  const settle = useCallback((value: boolean) => {
    const current = pendingRef.current;
    pendingRef.current = null;
    setPending(null);
    current?.resolve(value);
  }, []);

  const value = useMemo<ConfirmContextValue>(() => ({ confirm }), [confirm]);

  return (
    <ConfirmContext.Provider value={value}>
      {children}
      <Drawer
        open={pending !== null}
        onClose={() => settle(false)}
        title={pending?.options.title ?? 'Confirm'}
        footer={
          pending ? (
            <div className="inline-actions inline-actions-end">
              <button type="button" className="button button-light" onClick={() => settle(false)}>
                {pending.options.cancelLabel ?? 'Cancel'}
              </button>
              <button
                type="button"
                className={pending.options.destructive ? 'button button-danger' : 'button button-primary'}
                onClick={() => settle(true)}
              >
                {pending.options.confirmLabel ?? 'Confirm'}
              </button>
            </div>
          ) : null
        }
      >
        <div className="confirm-body">{pending?.options.message}</div>
      </Drawer>
    </ConfirmContext.Provider>
  );
}

export function useConfirm(): ConfirmContextValue['confirm'] {
  const context = useContext(ConfirmContext);
  if (!context) {
    throw new Error('useConfirm must be used inside <ConfirmProvider>.');
  }
  return context.confirm;
}

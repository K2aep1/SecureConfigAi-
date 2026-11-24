/**
 * Drawer.
 *
 * Used for evidence, AI output, exemptions and destructive confirmations.
 * Accessibility contract: `role="dialog"` + `aria-modal`, labelled by its
 * heading, Escape closes, focus moves in on open and returns to the trigger on
 * close, and the page behind is scroll-locked.
 */

import { useEffect, useId, useRef, type ReactNode } from 'react';
import { createPortal } from 'react-dom';
import clsx from 'clsx';

export function Drawer({
  open,
  onClose,
  title,
  subtitle,
  children,
  footer,
  width = 'regular',
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  subtitle?: ReactNode;
  children: ReactNode;
  footer?: ReactNode;
  width?: 'regular' | 'wide';
}) {
  const headingId = useId();
  const panelRef = useRef<HTMLDivElement>(null);
  const previouslyFocused = useRef<HTMLElement | null>(null);

  useEffect(() => {
    if (!open) return;

    previouslyFocused.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;

    const panel = panelRef.current;
    const focusable = panel?.querySelector<HTMLElement>(
      'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
    );
    (focusable ?? panel)?.focus();

    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';

    function onKeyDown(event: KeyboardEvent) {
      if (event.key === 'Escape') {
        event.stopPropagation();
        onClose();
      }
    }

    document.addEventListener('keydown', onKeyDown);
    return () => {
      document.removeEventListener('keydown', onKeyDown);
      document.body.style.overflow = previousOverflow;
      previouslyFocused.current?.focus();
    };
  }, [open, onClose]);

  if (!open) return null;

  // Render at document.body level so fixed positioning and z-index are not
  // constrained by transformed/overflow-hidden application containers.
  return createPortal(
    <div className="drawer-layer">
      <button
        type="button"
        className="drawer-overlay"
        aria-label="Close panel"
        tabIndex={-1}
        onClick={onClose}
      />
      <div
        className={clsx('drawer', width === 'wide' && 'drawer-wide')}
        role="dialog"
        aria-modal="true"
        aria-labelledby={headingId}
        ref={panelRef}
        tabIndex={-1}
      >
        <header className="drawer-head">
          <div>
            <h2 className="drawer-title" id={headingId}>
              {title}
            </h2>
            {subtitle ? <div className="drawer-subtitle">{subtitle}</div> : null}
          </div>
          <button type="button" className="drawer-close" onClick={onClose} aria-label="Close panel">
            <span aria-hidden="true">×</span>
          </button>
        </header>
        <div className="drawer-body">{children}</div>
        {footer ? <footer className="drawer-foot">{footer}</footer> : null}
      </div>
    </div>,
    document.body,
  );
}

// Modal overlays on the native <dialog>: focus trap, Escape and the top
// layer for free. A Sheet slides up from the bottom (phones), a Dialog sits
// in the middle.

import { useEffect, useRef, type ReactNode } from 'react';

import { IconButton } from './Button.tsx';

export function Dialog({
  open,
  onClose,
  label,
  children,
  variant = 'dialog',
}: {
  open: boolean;
  onClose: () => void;
  label: string;
  children: ReactNode;
  variant?: 'dialog' | 'sheet';
}) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const dialog = ref.current;
    if (!dialog) return;
    if (open && !dialog.open) dialog.showModal();
    if (!open && dialog.open) dialog.close();
  }, [open]);
  const sheet = variant === 'sheet';
  return (
    <dialog
      ref={ref}
      aria-label={label}
      onClose={onClose}
      onClick={(event) => {
        // A click on the backdrop lands on the dialog element itself.
        if (event.target === ref.current) onClose();
      }}
      style={{
        border: '1px solid var(--color-line-strong)',
        borderRadius: sheet
          ? 'var(--radius-sheet) var(--radius-sheet) 0 0'
          : 'var(--radius-overlay)',
        background: 'var(--color-bg)',
        color: 'var(--color-text)',
        boxShadow: sheet ? 'var(--shadow-sheet)' : 'var(--shadow-overlay)',
        padding: 0,
        width: sheet ? '100%' : 'min(480px, calc(100vw - 32px))',
        maxWidth: sheet ? '100%' : undefined,
        maxHeight: sheet ? '86vh' : 'calc(100vh - 64px)',
        margin: sheet ? 'auto 0 0' : 'auto',
        animation: `rise var(--duration-base) var(--ease-out) both`,
      }}
    >
      {open ? (
        <div
          style={{
            position: 'relative',
            padding: sheet ? '8px 16px 20px' : 20,
          }}
        >
          <div style={{ position: 'absolute', top: 6, right: 6 }}>
            <IconButton icon="close" label="Close" bare onClick={onClose} />
          </div>
          {children}
        </div>
      ) : null}
    </dialog>
  );
}

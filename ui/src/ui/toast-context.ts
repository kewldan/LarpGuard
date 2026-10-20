// Short confirmations: the context the ToastProvider fills and the hooks
// screens use.

import { createContext, use, useCallback } from 'react';

export const ToastContext = createContext<(message: string) => void>(
  () => undefined,
);

export function useToast(): (message: string) => void {
  return use(ToastContext);
}

export function useCopy(): (text: string, label?: string) => void {
  const toast = useToast();
  return useCallback(
    (text: string, label?: string) => {
      void navigator.clipboard.writeText(text).then(
        () => {
          toast(`Copied${label ? ` ${label}` : ''}`);
        },
        () => {
          toast('Copy failed: clipboard not available');
        },
      );
    },
    [toast],
  );
}

import { useSyncExternalStore } from 'react';

// Below the design's single breakpoint (760 px) screens switch to their
// phone layout.
const QUERY = '(max-width: 760px)';

function subscribe(listener: () => void): () => void {
  const media = window.matchMedia(QUERY);
  media.addEventListener('change', listener);
  return () => {
    media.removeEventListener('change', listener);
  };
}

export function useCompact(): boolean {
  return useSyncExternalStore(
    subscribe,
    () => window.matchMedia(QUERY).matches,
    () => false,
  );
}

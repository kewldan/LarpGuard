// Theme preference: the system's (prefers-color-scheme) unless the user
// picked one; the pick is a per-browser convenience in localStorage and
// lands on <html data-theme>.

import { useCallback, useSyncExternalStore } from 'react';

export type ThemeChoice = 'system' | 'dark' | 'light';
const KEY = 'larpguard.theme';
const listeners = new Set<() => void>();

function read(): ThemeChoice {
  try {
    const value = localStorage.getItem(KEY);
    return value === 'dark' || value === 'light' ? value : 'system';
  } catch {
    return 'system';
  }
}

function apply(choice: ThemeChoice): void {
  const root = document.documentElement;
  if (choice === 'system') delete root.dataset.theme;
  else root.dataset.theme = choice;
}

export function initTheme(): void {
  apply(read());
  window
    .matchMedia('(prefers-color-scheme: light)')
    .addEventListener('change', () => {
      for (const listener of listeners) listener();
    });
}

export function setTheme(choice: ThemeChoice): void {
  try {
    if (choice === 'system') localStorage.removeItem(KEY);
    else localStorage.setItem(KEY, choice);
  } catch {
    // Private mode: the choice lasts for this page only.
  }
  apply(choice);
  for (const listener of listeners) listener();
}

// The theme in effect, after the system preference.
export function effectiveTheme(): 'dark' | 'light' {
  const choice = read();
  if (choice !== 'system') return choice;
  return window.matchMedia('(prefers-color-scheme: light)').matches
    ? 'light'
    : 'dark';
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export function useTheme(): {
  choice: ThemeChoice;
  theme: 'dark' | 'light';
  toggle: () => void;
} {
  const choice = useSyncExternalStore(subscribe, read, () => 'system' as const);
  const theme = useSyncExternalStore(
    subscribe,
    effectiveTheme,
    () => 'dark' as const,
  );
  const toggle = useCallback(() => {
    setTheme(effectiveTheme() === 'dark' ? 'light' : 'dark');
  }, []);
  return { choice, theme, toggle };
}

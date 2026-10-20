import '@fontsource/schibsted-grotesk/400.css';
import '@fontsource/schibsted-grotesk/500.css';
import '@fontsource/schibsted-grotesk/600.css';
import '@fontsource/schibsted-grotesk/700.css';
import '@fontsource/jetbrains-mono/400.css';
import '@fontsource/jetbrains-mono/500.css';
import '@fontsource/jetbrains-mono/600.css';
import './design/tokens.css';
import './styles/base.css';

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { RouterProvider } from '@tanstack/react-router';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';

import { router } from './app/router.tsx';
import { ApiError } from './lib/api.ts';
import { initTheme } from './lib/theme.ts';
import { ToastProvider } from './ui/Toast.tsx';

initTheme();

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // Client errors (bad filter, missing) are final; retry the rest once.
      retry: (failures, error) =>
        !(
          error instanceof ApiError &&
          error.status >= 400 &&
          error.status < 500
        ) && failures < 1,
      refetchOnWindowFocus: true,
    },
  },
});

const root = document.getElementById('root');
if (root) {
  createRoot(root).render(
    <StrictMode>
      <QueryClientProvider client={queryClient}>
        <ToastProvider>
          <RouterProvider router={router} />
        </ToastProvider>
      </QueryClientProvider>
    </StrictMode>,
  );
}

/**
 * Application entry point.
 *
 * Provider order matters:
 *   ErrorBoundary → QueryClientProvider → ToastProvider → ConfirmProvider →
 *   BrowserRouter → SessionProvider → ScanTrackerProvider → App
 *
 * The toast provider is above the session and scan tracker because both report
 * through it; the error boundary is outermost so a crash in any provider still
 * renders something readable.
 */
import "@fontsource-variable/inter/wght.css";

import "@fontsource/ibm-plex-mono/400.css";
import "@fontsource/ibm-plex-mono/500.css";
import "@fontsource/ibm-plex-mono/600.css";

import "@fontsource/ibm-plex-sans-arabic/400.css";
import "@fontsource/ibm-plex-sans-arabic/500.css";
import "@fontsource/ibm-plex-sans-arabic/600.css";
import "@fontsource/ibm-plex-sans-arabic/700.css";
import React from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import { QueryClientProvider } from '@tanstack/react-query';
import App from './App';
import { createQueryClient } from './state/queryClient';
import { SessionProvider } from './auth/SessionProvider';
import { ScanTrackerProvider } from './state/ScanProvider';
import { ToastProvider } from './components/Toast';
import { ConfirmProvider } from './components/ConfirmDialog';
import { ErrorBoundary } from './components/ErrorBoundary';
import './index.css';

const queryClient = createQueryClient();

const rootElement = document.getElementById('root');
if (!rootElement) {
  throw new Error('Root element #root is missing from index.html.');
}

ReactDOM.createRoot(rootElement).render(
  <React.StrictMode>
    <ErrorBoundary scope="SecureConfigAI">
      <QueryClientProvider client={queryClient}>
        <ToastProvider>
          <ConfirmProvider>
            <BrowserRouter>
              <SessionProvider>
                <ScanTrackerProvider>
                  <App />
                </ScanTrackerProvider>
              </SessionProvider>
            </BrowserRouter>
          </ConfirmProvider>
        </ToastProvider>
      </QueryClientProvider>
    </ErrorBoundary>
  </React.StrictMode>,
);

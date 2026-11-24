/**
 * Opens a scan report artefact (HTML or PDF) in a new tab.
 *
 * Reports require a bearer token, so a plain `<a href>` cannot be used: the
 * artefact is fetched with the access token, turned into a blob URL and opened.
 * No cache-busting query string is ever added — the server's `ETag`/`304`
 * behaviour is what keeps repeated opens cheap. If a `304` ever surfaces to
 * JavaScript without a cached body, the request is retried once with
 * `cache: 'reload'` rather than failing.
 */

import { useCallback, useState } from 'react';
import { getScanReportHtml, getScanReportPdf } from '../api';
import { useToast } from '../components/Toast';
import { errorToastMessage } from '../lib/errors';

export type ReportFormat = 'html' | 'pdf';

interface PendingReport {
  scanId: string;
  format: ReportFormat;
}

export function useOpenReport() {
  const toast = useToast();
  const [pending, setPending] = useState<PendingReport | null>(null);

  const openReport = useCallback(
    async (scanId: string, format: ReportFormat): Promise<void> => {
      setPending({ scanId, format });
      try {
        const fetchReport = format === 'html' ? getScanReportHtml : getScanReportPdf;
        let response = await fetchReport(scanId);

        if (response.status === 304) {
          // The browser revalidated but had no cached body to hand back.
          response = await fetchReport(scanId, 'reload');
          if (response.status === 304) {
            throw new Error('The server reported the report as unchanged but no cached copy exists.');
          }
        }

        const blob = await response.blob();
        if (blob.size === 0) {
          throw new Error('The report artefact was empty.');
        }

        const url = URL.createObjectURL(blob);
        const opened = window.open(url, '_blank', 'noopener,noreferrer');
        if (!opened) {
          toast.push({
            tone: 'warning',
            title: 'The report was generated but the new tab was blocked',
            message: 'Allow pop-ups for this site to open report artefacts.',
          });
        } else {
          toast.push({
            tone: 'success',
            title: `${format.toUpperCase()} report opened`,
            message: 'Reports are ETag-validated, so reopening the same scan is served from cache.',
          });
        }
        // Give the new tab time to load the blob before releasing it.
        window.setTimeout(() => URL.revokeObjectURL(url), 60_000);
      } catch (error) {
        toast.push({
          tone: 'error',
          title: `Could not open the ${format.toUpperCase()} report`,
          message: errorToastMessage(error),
        });
      } finally {
        setPending(null);
      }
    },
    [toast],
  );

  const isPending = useCallback(
    (scanId: string, format: ReportFormat) =>
      pending !== null && pending.scanId === scanId && pending.format === format,
    [pending],
  );

  return { openReport, isPending };
}

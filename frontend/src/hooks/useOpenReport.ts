/**
 * Opens a scan report artefact (HTML or PDF).
 *
 * Reports require bearer-token authentication, so the artefact is fetched
 * through the API client and opened through a temporary Blob URL.
 *
 * Cache behaviour:
 * - No cache-busting query parameters.
 * - ETag validation remains the server's responsibility.
 * - A surfaced 304 without a usable body triggers one reload retry.
 *
 * Popup behaviour:
 * - Opens a temporary tab synchronously during the user interaction.
 * - Navigates that tab to the Blob URL after the report is available.
 *
 * Concurrency:
 * - Tracks pending operations independently by scan ID and format.
 */

import { useCallback, useState } from 'react';
import { getScanReportHtml, getScanReportPdf } from '../api';
import { useToast } from '../components/Toast';
import { errorToastMessage } from '../lib/errors';

export type ReportFormat = 'html' | 'pdf';


function reportKey(scanId: string, format: ReportFormat): string {
  return `${scanId}:${format}`;
}

export function useOpenReport() {
  const toast = useToast();
  const [pending, setPending] = useState<Set<string>>(() => new Set());

  const openReport = useCallback(
    async (scanId: string, format: ReportFormat): Promise<void> => {
      const key = reportKey(scanId, format);

      if (pending.has(key)) return;

      // Open synchronously to reduce popup-blocking risk.
      const reportWindow = window.open('about:blank', '_blank');

      if (!reportWindow) {
        toast.push({
          tone: 'warning',
          title: 'Pop-up blocked',
          message: 'Allow pop-ups for this site, then try opening the report again.',
        });
        return;
      }

      setPending((current) => new Set(current).add(key));

      try {
        const fetchReport =
          format === 'html' ? getScanReportHtml : getScanReportPdf;

        let response = await fetchReport(scanId);

        if (response.status === 304) {
          response = await fetchReport(scanId, 'reload');

          if (response.status === 304) {
            throw new Error(
              'The server returned 304, but no cached report body was available.',
            );
          }
        }

        if (!response.ok) {
          throw new Error(
            `Report request failed with HTTP ${response.status}.`,
          );
        }

        const blob = await response.blob();

        if (blob.size === 0) {
          throw new Error('The report artefact was empty.');
        }

        const url = URL.createObjectURL(blob);

        reportWindow.location.replace(url);

        // Keep the Blob URL alive long enough for the browser to load it.
        window.setTimeout(() => {
          URL.revokeObjectURL(url);
        }, 60_000);

        toast.push({
          tone: 'success',
          title: `${format.toUpperCase()} report opened`,
          message: 'The report was retrieved successfully.',
        });
      } catch (error) {
        reportWindow.close();
        toast.push({
          tone: 'error',
          title: `Could not open the ${format.toUpperCase()} report`,
          message: errorToastMessage(error),
        });
      } finally {
        setPending((current) => {
          const next = new Set(current);
          next.delete(key);
          return next;
        });
      }
    },
    [pending, toast],
  );

  const isPending = useCallback(
    (scanId: string, format: ReportFormat): boolean =>
      pending.has(reportKey(scanId, format)),
    [pending],
  );

  return { openReport, isPending };
}
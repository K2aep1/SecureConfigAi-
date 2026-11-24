/**
 * AI Assistant.
 *
 * Three advisory surfaces, all clearly marked as advisory:
 *   - a chat over `POST /ai/chat` with a paged session list;
 *   - scan-scoped actions (`/ai/report/{id}`, `/ai/scans/{id}/recommendations`,
 *     `/ai/risk-priorities/{id}`);
 *   - per-finding explanation via the shared findings table.
 *
 * Nothing on this page can change a control verdict, a score, coverage or risk.
 */

import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  deleteChatSession,
  generateAiReport,
  getAiStatus,
  getChatMessages,
  getRiskPriorities,
  getScanAiRecommendations,
  getScanResults,
  listChatSessions,
  queryKeys,
  sendChat,
} from '../api';
import { DEFAULT_PAGE_SIZE, useCursorList } from '../hooks/useCursorList';
import { useDocumentTitle, useNow } from '../hooks/useAppData';
import { ScanPicker } from '../components/ScanPicker';
import { DataTable, LoadMore, type Column } from '../components/DataTable';
import { NeutralBadge, SeverityBadge } from '../components/Badges';
import { EmptyState, ErrorState, LoadingState, Notice } from '../components/States';
import { FindingTable } from '../components/FindingTable';
import { FindingAiDrawer } from '../components/FindingAiDrawer';
import { MetricCard, MetricGrid } from '../components/MetricCard';
import { useConfirm } from '../components/ConfirmDialog';
import { useToast } from '../components/Toast';
import { errorToastMessage } from '../lib/errors';
import { formatRelative, humanize } from '../lib/format';
import type { AiScanRecommendationItem, ChatSession, Finding, PrioritizedFinding } from '../types';

const ADVISORY_STATEMENT =
  'AI output is advisory commentary. It is generated from evidence the deterministic engine already recorded, it cannot change a score, and it never decides whether a control is compliant.';

export default function AiAssistantPage() {
  useDocumentTitle('AI Assistant · SecureConfigAI');
  const toast = useToast();
  const confirm = useConfirm();
  const queryClient = useQueryClient();

  const [selectedScan, setSelectedScan] = useState<string | null>(null);
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [draft, setDraft] = useState('');
  const [explained, setExplained] = useState<Finding | null>(null);

  const status = useQuery({
    queryKey: queryKeys.ai.status(),
    staleTime: 60_000,
    retry: 0,
    queryFn: ({ signal }) => getAiStatus(signal),
  });

  const sessions = useCursorList<ChatSession>({
    queryKey: queryKeys.ai.sessions(),
    fetchPage: (cursor, signal) => listChatSessions({ limit: DEFAULT_PAGE_SIZE, cursor }, signal),
    staleTime: 10_000,
  });

  const messages = useQuery({
    queryKey: queryKeys.ai.messages(sessionId ?? 'none'),
    enabled: sessionId !== null,
    staleTime: 5_000,
    queryFn: ({ signal }) => {
      if (!sessionId) throw new Error('No session selected.');
      return getChatMessages(sessionId, signal);
    },
  });

  const send = useMutation({
    mutationFn: (content: string) => sendChat({ content, session_id: sessionId, scan_id: selectedScan }),
    onSuccess: (response) => {
      setSessionId(response.session_id);
      setDraft('');
      void queryClient.invalidateQueries({ queryKey: queryKeys.ai.sessions() });
      void queryClient.invalidateQueries({ queryKey: queryKeys.ai.messages(response.session_id) });
    },
    onError: (error) => {
      toast.push({
        tone: 'error',
        title: 'The assistant could not answer',
        message: errorToastMessage(error),
      });
    },
  });

  const removeSession = useMutation({
    mutationFn: (id: string) => deleteChatSession(id),
    onSuccess: () => {
      toast.push({ tone: 'success', title: 'Conversation deleted' });
      setSessionId(null);
      void queryClient.invalidateQueries({ queryKey: queryKeys.ai.sessions() });
    },
    onError: (error) => {
      toast.push({
        tone: 'error',
        title: 'Could not delete the conversation',
        message: errorToastMessage(error),
      });
    },
  });

  // Scan-scoped advisory queries: only run when a scan is actually chosen.
  const scanResults = useQuery({
    queryKey: queryKeys.scans.results(selectedScan ?? 'none'),
    enabled: selectedScan !== null,
    staleTime: 60_000,
    queryFn: () => {
      if (!selectedScan) throw new Error('No scan selected.');
      return getScanResults(selectedScan);
    },
  });

  const report = useMutation({
    mutationFn: (scanId: string) => generateAiReport(scanId),
    onError: (error) => {
      toast.push({
        tone: 'error',
        title: 'Could not generate the AI summary',
        message: errorToastMessage(error),
      });
    },
  });

  const recommendations = useMutation({
    mutationFn: (scanId: string) => getScanAiRecommendations(scanId),
    onError: (error) => {
      toast.push({
        tone: 'error',
        title: 'Could not load AI recommendations',
        message: errorToastMessage(error),
      });
    },
  });

  const priorities = useMutation({
    mutationFn: (scanId: string) => getRiskPriorities(scanId),
    onError: (error) => {
      toast.push({
        tone: 'error',
        title: 'Could not load risk priorities',
        message: errorToastMessage(error),
      });
    },
  });

  const tick = useNow(30_000, true);

  return (
    <div className="page">
      <div className="page-intro">
        <div>
          <span className="eyebrow">Advisory assistance</span>
          <h2>AI Assistant</h2>
          <p>
            Explanations and prioritisation drawn from stored evidence. The deterministic engine
            remains the only source of truth.
          </p>
        </div>
      </div>

      <Notice tone="info" title="Advisory only">
        {ADVISORY_STATEMENT}
      </Notice>

      <section className="panel">
        <div className="panel-head">
          <div>
            <h2>Provider status</h2>
            <p>Reported by `GET /ai/status` and cached by the API (at most one provider check per minute).</p>
          </div>
          <NeutralBadge
            label={status.data?.cached ? 'cached' : 'live'}
            title="Whether this status came from the API's cache."
          />
        </div>
        {status.isLoading ? <LoadingState label="Checking AI provider…" rows={1} compact /> : null}
        {status.isError ? (
          <ErrorState error={status.error} onRetry={() => void status.refetch()} scope="AI status" compact />
        ) : null}
        {status.data ? (
          <MetricGrid columns={4}>
            <MetricCard label="Provider" value={status.data.provider} />
            <MetricCard label="Model" value={status.data.model} />
            <MetricCard
              label="AI runtime"
              value={!status.data.enabled ? 'Disabled' : status.data.configured ? 'Configured' : 'No API key'}
              tone={status.data.enabled && status.data.configured ? 'ok' : 'warn'}
              note={!status.data.enabled ? 'Enable AI in backend settings' : status.data.configured ? 'Provider key detected' : 'Check backend/.env'}
            />
            <MetricCard
              label="API reachable"
              value={status.data.connected ? 'Yes' : 'No'}
              tone={status.data.connected ? 'ok' : 'warn'}
              note={`Checked ${formatRelative(status.data.checked_at, tick)} · reachability does not check credits`}
            />
          </MetricGrid>
        ) : null}
        {status.data && (!status.data.enabled || !status.data.configured || !status.data.connected) ? (
          <Notice tone="warning" title="AI provider is not ready">
            {status.data.error ?? 'Check the AI provider configuration and connection.'}
          </Notice>
        ) : null}
        {status.data?.connected && status.data.enabled && status.data.configured ? (
          <p className="muted ai-provider-note">
            This check confirms provider API reachability only. Text generation can still be rejected by billing/quota limits, project permissions, or model access. Any response marked LOCAL FALLBACK is deterministic text, not a model-generated answer.
          </p>
        ) : null}
      </section>

      <section className="chat-layout">
        <div className="panel">
          <div className="panel-head">
            <div>
              <h2>Conversations</h2>
              <p>{sessions.count} loaded</p>
            </div>
            <button
              type="button"
              className="text-button"
              onClick={() => {
                setSessionId(null);
                setDraft('');
              }}
            >
              New chat
            </button>
          </div>

          {sessions.isError ? (
            <ErrorState error={sessions.error} onRetry={sessions.reload} scope="Conversations" compact />
          ) : null}

          <div className="session-list">
            {sessions.items.map((session) => (
              <div
                key={session.id}
                className={`session${session.id === sessionId ? ' session-active' : ''}`}
              >
                <button
                  type="button"
                  className="session-open"
                  onClick={() => {
                    setSessionId(session.id);
                    const nextScan = session.scan_id ?? null;
                    if (nextScan !== selectedScan) {
                      report.reset();
                      recommendations.reset();
                      priorities.reset();
                      setSelectedScan(nextScan);
                    }
                  }}
                  aria-current={session.id === sessionId}
                >
                  <span className="session-title">{session.title}</span>
                  <span className="session-meta">
                    {session.created_at ? formatRelative(session.created_at, tick) : ''}
                    {session.scan_id ? ` · scan ${session.scan_id.slice(0, 8)}` : ''}
                  </span>
                </button>
                <button
                  type="button"
                  className="session-delete"
                  aria-label={`Delete conversation ${session.title}`}
                  onClick={async () => {
                    const confirmed = await confirm({
                      title: 'Delete this conversation?',
                      message: 'The messages are removed permanently.',
                      confirmLabel: 'Delete',
                      destructive: true,
                    });
                    if (confirmed) removeSession.mutate(session.id);
                  }}
                >
                  <span aria-hidden="true">×</span>
                </button>
              </div>
            ))}
            {!sessions.isLoading && sessions.items.length === 0 ? (
              <EmptyState
                title="No conversations yet"
                description="Ask a question below to start one."
                compact
              />
            ) : null}
          </div>

          <LoadMore
            hasMore={sessions.hasMore}
            isLoading={sessions.isLoadingMore}
            onLoadMore={sessions.loadMore}
            loadedCount={sessions.count}
            pageSize={DEFAULT_PAGE_SIZE}
            unit="conversations"
          />
        </div>

        <div className="panel chat-panel">
          <div className="panel-head">
            <div>
              <h2>{sessionId ? 'Conversation' : 'New conversation'}</h2>
              <p>
                Choose an assessment to give the assistant concrete scan context; without one, ask general security questions. The transcript is not a control assessment.
              </p>
            </div>
            <div className="page-intro-tools">
              <ScanPicker
                value={selectedScan}
                onChange={(next) => {
                  report.reset();
                  recommendations.reset();
                  priorities.reset();
                  if (next !== selectedScan) {
                    setSessionId(null);
                    setDraft('');
                  }
                  setSelectedScan(next);
                }}
                label="Scan context"
                id="ai-chat-scan-context"
                placeholder="General question — no scan"
              />
            </div>
          </div>

          <div className="chat-messages" aria-live="polite">
            {messages.isLoading ? <LoadingState label="Loading messages…" rows={3} compact /> : null}
            {messages.isError ? (
              <ErrorState
                error={messages.error}
                onRetry={() => void messages.refetch()}
                scope="Conversation"
                compact
              />
            ) : null}
            {(messages.data ?? []).map((message) => (
              <div
                key={message.id}
                className={`message${message.role === 'user' ? ' message-user' : ' message-assistant'}`}
              >
                <span className="message-role">{humanize(message.role)}</span>
                {message.role !== 'user' && message.content.includes('[LOCAL FALLBACK — NOT AI-GENERATED]') ? (
                  <span className="badge badge-warn ai-fallback-badge" role="status">
                    LOCAL FALLBACK · NOT AI-GENERATED
                  </span>
                ) : null}
                <p className="message-content">
                  {message.content.replace('[LOCAL FALLBACK — NOT AI-GENERATED]', '').trimStart()}
                </p>
              </div>
            ))}
            {!messages.isLoading && (messages.data ?? []).length === 0 ? (
              <EmptyState
                title="No messages in this conversation"
                description="Ask about a scan, a control, or a remediation step."
                compact
              />
            ) : null}
            {send.isPending ? (
              <div className="message message-assistant message-pending">
                <span className="message-role">Assistant</span>
                <p className="message-content">
                  <span className="spinner" aria-hidden="true" /> Thinking…
                </p>
              </div>
            ) : null}
          </div>

          <form
            className="chat-input"
            onSubmit={(event) => {
              event.preventDefault();
              const content = draft.trim();
              if (content.length === 0 || send.isPending) return;
              send.mutate(content);
            }}
          >
            <label className="visually-hidden" htmlFor="ai-chat-input">
              Message the assistant
            </label>
            <textarea
              id="ai-chat-input"
              value={draft}
              onChange={(event) => setDraft(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === 'Enter' && !event.shiftKey) {
                  event.preventDefault();
                  const content = draft.trim();
                  if (content.length > 0 && !send.isPending) send.mutate(content);
                }
              }}
              rows={2}
              placeholder={selectedScan ? 'Ask about the selected assessment… (Enter to send)' : 'Ask a general security question, or select a scan above… (Enter to send)'}
            />
            <button type="submit" className="button button-primary" disabled={send.isPending || draft.trim() === ''}>
              {send.isPending ? 'Sending…' : 'Send'}
            </button>
          </form>
        </div>
      </section>

      <section className="panel">
        <div className="panel-head">
          <div>
            <h2>Scan advisory</h2>
            <p>
              Summary, recommendations and fix-first ordering for a chosen scan. Every item is
              advisory and cannot alter the scan's stored results.
            </p>
          </div>
        </div>

        <div className="inline-actions">
          <button
            type="button"
            className="button button-light"
            onClick={() => selectedScan && report.mutate(selectedScan)}
            disabled={selectedScan === null || report.isPending}
          >
            {report.isPending ? 'Summarising…' : 'Explain latest assessment'}
          </button>
          <button
            type="button"
            className="button button-light"
            onClick={() => selectedScan && recommendations.mutate(selectedScan)}
            disabled={selectedScan === null || recommendations.isPending}
          >
            {recommendations.isPending ? 'Loading…' : 'Recommendations'}
          </button>
          <button
            type="button"
            className="button button-light"
            onClick={() => selectedScan && priorities.mutate(selectedScan)}
            disabled={selectedScan === null || priorities.isPending}
          >
            {priorities.isPending ? 'Loading…' : 'What to fix first'}
          </button>
        </div>

        {selectedScan === null ? (
          <EmptyState
            title="Choose a scan"
            description="Advisory actions are scoped to one scan so the commentary always has a defined evidence base."
            compact
          />
        ) : null}

        {report.data ? (
          <div className="ai-result">
            <h3 className="drawer-section-title">Assessment summary (advisory)</h3>
            <p className="ai-text">{report.data.summary}</p>
            <p className="drawer-text-subtle">
              Model {report.data.model_used}
              {report.data.cached ? ' · served from cache' : ''}
            </p>
          </div>
        ) : null}

        {recommendations.data ? (
          <div className="ai-result">
            <h3 className="drawer-section-title">Recommendations (advisory)</h3>
            {recommendations.data.recommendations.length === 0 ? (
              <EmptyState title="No recommendations returned" compact />
            ) : (
              <DataTable
                columns={recommendationColumns}
                rows={recommendations.data.recommendations}
                rowKey={(row, index) => row.finding_id ?? row.control_id ?? `recommendation-${index}`}
                caption="AI recommendations for the selected scan"
                empty={<EmptyState title="No recommendations" compact />}
              />
            )}
          </div>
        ) : null}

        {priorities.data ? (
          <div className="ai-result">
            <h3 className="drawer-section-title">Fix first (advisory)</h3>
            <MetricGrid columns={2}>
              <MetricCard
                label="First priority"
                value={priorities.data.fix_first ? priorities.data.fix_first.title : 'Nothing outstanding'}
                note={
                  priorities.data.fix_first
                    ? `${priorities.data.fix_first.priority} · ${priorities.data.fix_first.severity} · ${priorities.data.fix_first.category}`
                    : 'No findings were ranked for this scan.'
                }
              />
              <MetricCard
                label="Prioritised findings"
                value={priorities.data.prioritized_findings.length}
                note="Ranked deterministically by severity and control weight"
              />
            </MetricGrid>
            {priorities.data.prioritized_findings.length === 0 ? (
              <EmptyState title="No prioritised findings returned" compact />
            ) : (
              <DataTable
                columns={priorityColumns}
                rows={priorities.data.prioritized_findings}
                rowKey={(row, index) => row.finding_id ?? `priority-${index}`}
                caption="AI prioritised findings for the selected scan"
                empty={<EmptyState title="No priorities" compact />}
              />
            )}
          </div>
        ) : null}
      </section>

      <section className="panel">
        <div className="panel-head">
          <div>
            <h2>Explain findings</h2>
            <p>
              Findings from the selected scan. &ldquo;Explain&rdquo; opens advisory commentary beside
              the recorded values.
            </p>
          </div>
        </div>
        {selectedScan === null ? (
          <EmptyState
            title="Choose a scan to list its findings"
            description="Findings come from the deterministic assessment; the AI only comments on them."
            compact
          />
        ) : scanResults.isLoading ? (
          <LoadingState label="Loading findings…" rows={2} compact />
        ) : scanResults.isError ? (
          <ErrorState
            error={scanResults.error}
            onRetry={() => void scanResults.refetch()}
            scope="Findings"
            compact
          />
        ) : (
          <FindingTable
            findings={scanResults.data?.findings ?? []}
            onExplain={setExplained}
            emptyTitle="This scan recorded no findings"
            emptyDescription="Confirm coverage before treating that as a clean result."
          />
        )}
      </section>

      <FindingAiDrawer finding={explained} onClose={() => setExplained(null)} />
    </div>
  );
}

/**
 * `GET /ai/scans/{scan_id}/recommendations` returns flat remediation fields per
 * finding (not a nested `recommendation` object).
 */
const recommendationColumns: Column<AiScanRecommendationItem>[] = [
  {
    id: 'finding',
    header: 'Finding',
    width: '24%',
    cell: (row) => (
      <span className="cell-stack">
        <span className="cell-title">{row.title}</span>
        <code className="cell-code">{row.finding_id}</code>
      </span>
    ),
  },
  {
    id: 'priority',
    header: 'Priority',
    width: '12%',
    cell: (row) => <NeutralBadge label={humanize(row.priority)} />,
  },
  {
    id: 'severity',
    header: 'Severity',
    width: '12%',
    cell: (row) => <SeverityBadge severity={row.severity} />,
  },
  {
    id: 'advice',
    header: 'Advisory recommendation',
    cell: (row) => (
      <span className="cell-stack">
        <span>{row.what_should_be_done}</span>
        <span className="cell-subtle">{row.why_it_matters}</span>
        {row.verify ? (
          <span className="cell-subtle mono">verify: {row.verify}</span>
        ) : null}
      </span>
    ),
  },
];

/**
 * `GET /ai/risk-priorities/{scan_id}` is described by the API as deterministic
 * ranking, not model output: severity and control weight decide the order.
 */
const priorityColumns: Column<PrioritizedFinding>[] = [
  {
    id: 'priority',
    header: 'Priority',
    width: '12%',
    cell: (row) => <NeutralBadge label={humanize(row.priority)} />,
  },
  {
    id: 'finding',
    header: 'Finding',
    width: '28%',
    cell: (row) => (
      <span className="cell-stack">
        <span className="cell-title">{row.title}</span>
        <code className="cell-code">{row.finding_id}</code>
      </span>
    ),
  },
  {
    id: 'severity',
    header: 'Severity',
    width: '12%',
    cell: (row) => <SeverityBadge severity={row.severity} />,
  },
  {
    id: 'score',
    header: 'Score / weight',
    width: '14%',
    cell: (row) => (
      <span className="cell-stack">
        <span>score {row.score}</span>
        <span className="cell-subtle">weight {row.weight ?? '—'}</span>
      </span>
    ),
  },
  {
    id: 'context',
    header: 'Category / contribution',
    cell: (row) => (
      <span className="cell-stack">
        <span>{row.category}</span>
        <span className="cell-subtle">
          risk contribution {row.risk_contribution ?? '—'}
        </span>
      </span>
    ),
  },
];

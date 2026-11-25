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

import { useState, type FormEvent, type KeyboardEvent } from 'react';
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
import type {
  AiScanRecommendationItem,
  ChatSession,
  Finding,
  PrioritizedFinding,
} from '../types';

/* ---------- Types derived from the API, so no unseen type names are needed ---------- */

type AiStatus = Awaited<ReturnType<typeof getAiStatus>>;
type ChatMessage = Awaited<ReturnType<typeof getChatMessages>>[number];
type Tick = ReturnType<typeof useNow>;
type ErrorReporter = (title: string) => (error: unknown) => void;
type ScanAdvisory = ReturnType<typeof useScanAdvisory>;

/* ---------- Constants ---------- */

const ADVISORY_STATEMENT =
  'AI output is advisory commentary. It is generated from evidence the deterministic engine already recorded, it cannot change a score, and it never decides whether a control is compliant.';

const LOCAL_FALLBACK_MARKER = '[LOCAL FALLBACK — NOT AI-GENERATED]';

const TICK_MS = 30_000;
const STATUS_STALE_MS = 60_000;
const SESSIONS_STALE_MS = 10_000;
const MESSAGES_STALE_MS = 5_000;
const RESULTS_STALE_MS = 60_000;

/* ---------- Pure helpers ---------- */

function splitFallbackMarker(content: string) {
  return {
    isFallback: content.includes(LOCAL_FALLBACK_MARKER),
    text: content.replace(LOCAL_FALLBACK_MARKER, '').trimStart(),
  };
}

function aiRuntime(status: AiStatus) {
  if (!status.enabled) {
    return { value: 'Disabled', note: 'Enable AI in backend settings', ready: false };
  }
  if (!status.configured) {
    return { value: 'No API key', note: 'Check backend/.env', ready: false };
  }
  return { value: 'Configured', note: 'Provider key detected', ready: true };
}

function isProviderReady(status: AiStatus): boolean {
  return (
    status.enabled === true &&
    status.configured === true &&
    status.connected === true
  );
}

/* ---------- Shared hooks ---------- */

/** Returns a factory: `reportError('Title')` yields an `onError` that shows an error toast. */
function useErrorReporter(): ErrorReporter {
  const toast = useToast();
  return (title) => (error) =>
    toast.push({ tone: 'error', title, message: errorToastMessage(error) });
}

/** Scan-scoped advisory mutations, grouped so one `reset()` clears all three. */
function useScanAdvisory(reportError: ErrorReporter) {
  const report = useMutation({
    mutationFn: (scanId: string) => generateAiReport(scanId),
    onError: reportError('Could not generate the AI summary'),
  });

  const recommendations = useMutation({
    mutationFn: (scanId: string) => getScanAiRecommendations(scanId),
    onError: reportError('Could not load AI recommendations'),
  });

  const priorities = useMutation({
    mutationFn: (scanId: string) => getRiskPriorities(scanId),
    onError: reportError('Could not load risk priorities'),
  });

  function reset() {
    report.reset();
    recommendations.reset();
    priorities.reset();
  }

  return { report, recommendations, priorities, reset };
}

/* ---------- Page ---------- */

export default function AiAssistantPage() {
  useDocumentTitle('AI Assistant · SecureConfigAI');

  const toast = useToast();
  const queryClient = useQueryClient();
  const reportError = useErrorReporter();
  const advisory = useScanAdvisory(reportError);
  const tick = useNow(TICK_MS, true);

  const [selectedScan, setSelectedScan] = useState<string | null>(null);
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [draft, setDraft] = useState('');
  const [explained, setExplained] = useState<Finding | null>(null);

  const send = useMutation({
    mutationFn: (content: string) =>
      sendChat({ content, session_id: sessionId, scan_id: selectedScan }),
    onSuccess: (response) => {
      setSessionId(response.session_id);
      setDraft('');
      void queryClient.invalidateQueries({ queryKey: queryKeys.ai.sessions() });
      void queryClient.invalidateQueries({ queryKey: queryKeys.ai.messages(response.session_id) });
    },
    onError: reportError('The assistant could not answer'),
  });

  const removeSession = useMutation({
    mutationFn: (id: string) => deleteChatSession(id),
    onSuccess: () => {
      toast.push({ tone: 'success', title: 'Conversation deleted' });
      setSessionId(null);
      void queryClient.invalidateQueries({ queryKey: queryKeys.ai.sessions() });
    },
    onError: reportError('Could not delete the conversation'),
  });

  /** Picking a different scan (from the picker) clears the open conversation and draft. */
  function changeScan(next: string | null) {
    advisory.reset();
    if (next !== selectedScan) {
      setSessionId(null);
      setDraft('');
    }
    setSelectedScan(next);
  }

  /** Opening a conversation adopts its scan, and only resets advisory when the scan changes. */
  function openSession(session: ChatSession) {
    setSessionId(session.id);
    const nextScan = session.scan_id ?? null;
    if (nextScan !== selectedScan) {
      advisory.reset();
      setSelectedScan(nextScan);
    }
  }

  function startNewChat() {
    setSessionId(null);
    setDraft('');
  }

  return (
    <div className="page">
      <PageIntro />

      <Notice tone="info" title="Advisory only">
        {ADVISORY_STATEMENT}
      </Notice>

      <ProviderStatusPanel tick={tick} />

      <section className="chat-layout">
        <ConversationList
          activeId={sessionId}
          tick={tick}
          onOpen={openSession}
          onNew={startNewChat}
          onDelete={(id) => removeSession.mutate(id)}
        />
        <ChatPanel
          sessionId={sessionId}
          selectedScan={selectedScan}
          draft={draft}
          sending={send.isPending}
          onDraftChange={setDraft}
          onScanChange={changeScan}
          onSend={(content) => send.mutate(content)}
        />
      </section>

      <ScanAdvisoryPanel selectedScan={selectedScan} advisory={advisory} />

      <ExplainFindingsPanel selectedScan={selectedScan} onExplain={setExplained} />

      <FindingAiDrawer finding={explained} onClose={() => setExplained(null)} />
    </div>
  );
}

/* ---------- Sections ---------- */

function PageIntro() {
  return (
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
  );
}

function ProviderStatusPanel({ tick }: { tick: Tick }) {
  const status = useQuery({
    queryKey: queryKeys.ai.status(),
    staleTime: STATUS_STALE_MS,
    retry: 0,
    queryFn: ({ signal }) => getAiStatus(signal),
  });

  const data = status.data;

  return (
    <section className="panel">
      <div className="panel-head">
        <div>
          <h2>Provider status</h2>
          <p>
            Reported by `GET /ai/status` and cached by the API (at most one provider check per
            minute).
          </p>
        </div>
        <NeutralBadge
          label={data?.cached ? 'cached' : 'live'}
          title="Whether this status came from the API's cache."
        />
      </div>

      {status.isLoading ? <LoadingState label="Checking AI provider…" rows={1} compact /> : null}
      {status.isError ? (
        <ErrorState error={status.error} onRetry={() => void status.refetch()} scope="AI status" compact />
      ) : null}

      {data ? <ProviderMetrics status={data} tick={tick} /> : null}

      {data && !isProviderReady(data) ? (
        <Notice tone="warning" title="AI provider is not ready">
          {data.error ?? 'Check the AI provider configuration and connection.'}
        </Notice>
      ) : null}

      {data && isProviderReady(data) ? (
        <p className="muted ai-provider-note">
          This check confirms provider API reachability only. Text generation can still be rejected by
          billing/quota limits, project permissions, or model access. Any response marked LOCAL FALLBACK
          is deterministic text, not a model-generated answer.
        </p>
      ) : null}
    </section>
  );
}

function ProviderMetrics({ status, tick }: { status: AiStatus; tick: Tick }) {
  const runtime = aiRuntime(status);

  return (
    <MetricGrid columns={4}>
      <MetricCard label="Provider" value={status.provider} />
      <MetricCard label="Model" value={status.model} />
      <MetricCard
        label="AI runtime"
        value={runtime.value}
        tone={runtime.ready ? 'ok' : 'warn'}
        note={runtime.note}
      />
      <MetricCard
        label="API reachable"
        value={status.connected ? 'Yes' : 'No'}
        tone={status.connected ? 'ok' : 'warn'}
        note={`Checked ${formatRelative(status.checked_at, tick)} · reachability does not check credits`}
      />
    </MetricGrid>
  );
}

function ConversationList({
  activeId,
  tick,
  onOpen,
  onNew,
  onDelete,
}: {
  activeId: string | null;
  tick: Tick;
  onOpen: (session: ChatSession) => void;
  onNew: () => void;
  onDelete: (id: string) => void;
}) {
  const confirm = useConfirm();

  const sessions = useCursorList<ChatSession>({
    queryKey: queryKeys.ai.sessions(),
    fetchPage: (cursor, signal) => listChatSessions({ limit: DEFAULT_PAGE_SIZE, cursor }, signal),
    staleTime: SESSIONS_STALE_MS,
  });

  async function confirmDelete(session: ChatSession) {
    const confirmed = await confirm({
      title: 'Delete this conversation?',
      message: 'The messages are removed permanently.',
      confirmLabel: 'Delete',
      destructive: true,
    });
    if (confirmed) onDelete(session.id);
  }

  return (
    <div className="panel">
      <div className="panel-head">
        <div>
          <h2>Conversations</h2>
          <p>{sessions.count} loaded</p>
        </div>
        <button type="button" className="text-button" onClick={onNew}>
          New chat
        </button>
      </div>

      {sessions.isError ? (
        <ErrorState error={sessions.error} onRetry={sessions.reload} scope="Conversations" compact />
      ) : null}

      <div className="session-list">
        {sessions.items.map((session) => {
          const active = session.id === activeId;
          return (
            <div key={session.id} className={`session${active ? ' session-active' : ''}`}>
              <button
                type="button"
                className="session-open"
                onClick={() => onOpen(session)}
                aria-current={active}
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
                onClick={() => void confirmDelete(session)}
              >
                <span aria-hidden="true">×</span>
              </button>
            </div>
          );
        })}

        {!sessions.isLoading && sessions.items.length === 0 ? (
          <EmptyState title="No conversations yet" description="Ask a question below to start one." compact />
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
  );
}

function ChatPanel({
  sessionId,
  selectedScan,
  draft,
  sending,
  onDraftChange,
  onScanChange,
  onSend,
}: {
  sessionId: string | null;
  selectedScan: string | null;
  draft: string;
  sending: boolean;
  onDraftChange: (value: string) => void;
  onScanChange: (scanId: string | null) => void;
  onSend: (content: string) => void;
}) {
  const messages = useQuery({
    queryKey: queryKeys.ai.messages(sessionId ?? 'none'),
    enabled: sessionId !== null,
    staleTime: MESSAGES_STALE_MS,
    queryFn: ({ signal }) => {
      if (!sessionId) throw new Error('No session selected.');
      return getChatMessages(sessionId, signal);
    },
  });

  const transcript = messages.data ?? [];
  const trimmed = draft.trim();
  const canSend = trimmed.length > 0 && !sending;

  function submit() {
    if (canSend) onSend(trimmed);
  }

  return (
    <div className="panel chat-panel">
      <div className="panel-head">
        <div>
          <h2>{sessionId ? 'Conversation' : 'New conversation'}</h2>
          <p>
            Choose an assessment to give the assistant concrete scan context; without one, ask general
            security questions. The transcript is not a control assessment.
          </p>
        </div>
        <div className="page-intro-tools">
          <ScanPicker
            value={selectedScan}
            onChange={onScanChange}
            label="Scan context"
            id="ai-chat-scan-context"
            placeholder="General question — no scan"
          />
        </div>
      </div>

      <div className="chat-messages" aria-live="polite">
        {messages.isLoading ? <LoadingState label="Loading messages…" rows={3} compact /> : null}
        {messages.isError ? (
          <ErrorState error={messages.error} onRetry={() => void messages.refetch()} scope="Conversation" compact />
        ) : null}

        {transcript.map((message) => (
          <ChatMessageBubble key={message.id} message={message} />
        ))}

        {!messages.isLoading && transcript.length === 0 ? (
          <EmptyState
            title="No messages in this conversation"
            description="Ask about a scan, a control, or a remediation step."
            compact
          />
        ) : null}

        {sending ? (
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
        onSubmit={(event: FormEvent<HTMLFormElement>) => {
          event.preventDefault();
          submit();
        }}
      >
        <label className="visually-hidden" htmlFor="ai-chat-input">
          Message the assistant
        </label>
        <textarea
          id="ai-chat-input"
          value={draft}
          onChange={(event) => onDraftChange(event.target.value)}
          onKeyDown={(event: KeyboardEvent<HTMLTextAreaElement>) => {
            if (event.key === 'Enter' && !event.shiftKey) {
              event.preventDefault();
              submit();
            }
          }}
          rows={2}
          placeholder={
            selectedScan
              ? 'Ask about the selected assessment… (Enter to send)'
              : 'Ask a general security question, or select a scan above… (Enter to send)'
          }
        />
        <button type="submit" className="button button-primary" disabled={!canSend}>
          {sending ? 'Sending…' : 'Send'}
        </button>
      </form>
    </div>
  );
}

function ChatMessageBubble({ message }: { message: ChatMessage }) {
  const isUser = message.role === 'user';
  const { isFallback, text } = splitFallbackMarker(message.content);

  return (
    <div className={`message${isUser ? ' message-user' : ' message-assistant'}`}>
      <span className="message-role">{humanize(message.role)}</span>
      {!isUser && isFallback ? (
        <span className="badge badge-warn ai-fallback-badge" role="status">
          LOCAL FALLBACK · NOT AI-GENERATED
        </span>
      ) : null}
      <p className="message-content">{text}</p>
    </div>
  );
}

function ScanAdvisoryPanel({
  selectedScan,
  advisory,
}: {
  selectedScan: string | null;
  advisory: ScanAdvisory;
}) {
  const { report, recommendations, priorities } = advisory;
  const noScan = selectedScan === null;

  return (
    <section className="panel">
      <div className="panel-head">
        <div>
          <h2>Scan advisory</h2>
          <p>
            Summary, recommendations and fix-first ordering for a chosen scan. Every item is advisory
            and cannot alter the scan&apos;s stored results.
          </p>
        </div>
      </div>

      <div className="inline-actions">
        <button
          type="button"
          className="button button-light"
          onClick={() => {
            if (selectedScan) report.mutate(selectedScan);
          }}
          disabled={noScan || report.isPending}
        >
          {report.isPending ? 'Summarising…' : 'Explain latest assessment'}
        </button>
        <button
          type="button"
          className="button button-light"
          onClick={() => {
            if (selectedScan) recommendations.mutate(selectedScan);
          }}
          disabled={noScan || recommendations.isPending}
        >
          {recommendations.isPending ? 'Loading…' : 'Recommendations'}
        </button>
        <button
          type="button"
          className="button button-light"
          onClick={() => {
            if (selectedScan) priorities.mutate(selectedScan);
          }}
          disabled={noScan || priorities.isPending}
        >
          {priorities.isPending ? 'Loading…' : 'What to fix first'}
        </button>
      </div>

      {noScan ? (
        <EmptyState
          title="Choose a scan"
          description="Advisory actions are scoped to one scan so the commentary always has a defined evidence base."
          compact
        />
      ) : null}

      {report.data ? <SummaryResult result={report.data} /> : null}
      {recommendations.data ? <RecommendationsResult result={recommendations.data} /> : null}
      {priorities.data ? <PrioritiesResult result={priorities.data} /> : null}
    </section>
  );
}

type SummaryData = NonNullable<ScanAdvisory['report']['data']>;
type RecommendationsData = NonNullable<ScanAdvisory['recommendations']['data']>;
type PrioritiesData = NonNullable<ScanAdvisory['priorities']['data']>;

function SummaryResult({ result }: { result: SummaryData }) {
  return (
    <div className="ai-result">
      <h3 className="drawer-section-title">Assessment summary (advisory)</h3>
      <p className="ai-text">{result.summary}</p>
      <p className="drawer-text-subtle">
        Model {result.model_used}
        {result.cached ? ' · served from cache' : ''}
      </p>
    </div>
  );
}

function RecommendationsResult({ result }: { result: RecommendationsData }) {
  return (
    <div className="ai-result">
      <h3 className="drawer-section-title">Recommendations (advisory)</h3>
      {result.recommendations.length === 0 ? (
        <EmptyState title="No recommendations returned" compact />
      ) : (
        <DataTable
          columns={RECOMMENDATION_COLUMNS}
          rows={result.recommendations}
          rowKey={(row, index) => row.finding_id ?? row.control_id ?? `recommendation-${index}`}
          caption="AI recommendations for the selected scan"
          empty={<EmptyState title="No recommendations" compact />}
        />
      )}
    </div>
  );
}

function PrioritiesResult({ result }: { result: PrioritiesData }) {
  return (
    <div className="ai-result">
      <h3 className="drawer-section-title">Fix first (advisory)</h3>
      <MetricGrid columns={2}>
        <MetricCard
          label="First priority"
          value={result.fix_first ? result.fix_first.title : 'Nothing outstanding'}
          note={
            result.fix_first
              ? `${result.fix_first.priority} · ${result.fix_first.severity} · ${result.fix_first.category}`
              : 'No findings were ranked for this scan.'
          }
        />
        <MetricCard
          label="Prioritised findings"
          value={result.prioritized_findings.length}
          note="Ranked deterministically by severity and control weight"
        />
      </MetricGrid>
      {result.prioritized_findings.length === 0 ? (
        <EmptyState title="No prioritised findings returned" compact />
      ) : (
        <DataTable
          columns={PRIORITY_COLUMNS}
          rows={result.prioritized_findings}
          rowKey={(row, index) => row.finding_id ?? `priority-${index}`}
          caption="AI prioritised findings for the selected scan"
          empty={<EmptyState title="No priorities" compact />}
        />
      )}
    </div>
  );
}

function ExplainFindingsPanel({
  selectedScan,
  onExplain,
}: {
  selectedScan: string | null;
  onExplain: (finding: Finding) => void;
}) {
  const scanResults = useQuery({
    queryKey: queryKeys.scans.results(selectedScan ?? 'none'),
    enabled: selectedScan !== null,
    staleTime: RESULTS_STALE_MS,
    queryFn: () => {
      if (!selectedScan) throw new Error('No scan selected.');
      return getScanResults(selectedScan);
    },
  });

  return (
    <section className="panel">
      <div className="panel-head">
        <div>
          <h2>Explain findings</h2>
          <p>
            Findings from the selected scan. &ldquo;Explain&rdquo; opens advisory commentary beside the
            recorded values.
          </p>
        </div>
      </div>
      {renderFindingsBody(selectedScan, scanResults, onExplain)}
    </section>
  );
}

function renderFindingsBody(
  selectedScan: string | null,
  scanResults: ReturnType<typeof useQuery<Awaited<ReturnType<typeof getScanResults>>>>,
  onExplain: (finding: Finding) => void,
) {
  if (selectedScan === null) {
    return (
      <EmptyState
        title="Choose a scan to list its findings"
        description="Findings come from the deterministic assessment; the AI only comments on them."
        compact
      />
    );
  }
  if (scanResults.isLoading) {
    return <LoadingState label="Loading findings…" rows={2} compact />;
  }
  if (scanResults.isError) {
    return (
      <ErrorState
        error={scanResults.error}
        onRetry={() => void scanResults.refetch()}
        scope="Findings"
        compact
      />
    );
  }
  return (
    <FindingTable
      findings={scanResults.data?.findings ?? []}
      onExplain={onExplain}
      emptyTitle="This scan recorded no findings"
      emptyDescription="Confirm coverage before treating that as a clean result."
    />
  );
}

/* ---------- Table columns (module level, built once) ---------- */

/**
 * `GET /ai/scans/{scan_id}/recommendations` returns flat remediation fields per
 * finding (not a nested `recommendation` object).
 */
const RECOMMENDATION_COLUMNS: Column<AiScanRecommendationItem>[] = [
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
        {row.verify ? <span className="cell-subtle mono">verify: {row.verify}</span> : null}
      </span>
    ),
  },
];

/**
 * `GET /ai/risk-priorities/{scan_id}` is described by the API as deterministic
 * ranking, not model output: severity and control weight decide the order.
 */
const PRIORITY_COLUMNS: Column<PrioritizedFinding>[] = [
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
        <span className="cell-subtle">risk contribution {row.risk_contribution ?? '—'}</span>
      </span>
    ),
  },
];
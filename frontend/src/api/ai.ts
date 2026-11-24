/**
 * Contract §8 — AI (advisory only).
 *
 * Nothing here can change a score: every response is prose or a suggestion, and
 * the UI labels it as advisory (requirement 11).
 */

import { API_PREFIX, apiRequest, toPage } from './client';
import type {
  AiExplanation,
  AiFindingRecommendation,
  AiReport,
  AiRiskPriorities,
  AiScanRecommendations,
  AiStatus,
  ChatMessage,
  ChatRequest,
  ChatResponse,
  ChatSession,
  Page,
  PageParams,
} from '../types';

const AI = `${API_PREFIX}/ai`;

/** `GET /ai/status` — cached provider status (at most one provider call per 60 s). */
export function getAiStatus(signal?: AbortSignal): Promise<AiStatus> {
  return apiRequest<AiStatus>(`${AI}/status`, { signal });
}

/** `POST /ai/report/{scan_id}` */
export function generateAiReport(scanId: string): Promise<AiReport> {
  return apiRequest<AiReport>(`${AI}/report/${encodeURIComponent(scanId)}`, { method: 'POST' });
}

/** `POST /ai/findings/{finding_id}/explain` */
export function explainFinding(findingId: string): Promise<AiExplanation> {
  return apiRequest<AiExplanation>(
    `${AI}/findings/${encodeURIComponent(findingId)}/explain`,
    { method: 'POST' },
  );
}

/** `POST /ai/findings/{finding_id}/recommend` */
export function recommendForFinding(findingId: string): Promise<AiFindingRecommendation> {
  return apiRequest<AiFindingRecommendation>(
    `${AI}/findings/${encodeURIComponent(findingId)}/recommend`,
    { method: 'POST' },
  );
}

/** `GET /ai/scans/{scan_id}/recommendations` */
export function getScanAiRecommendations(scanId: string): Promise<AiScanRecommendations> {
  return apiRequest<AiScanRecommendations>(
    `${AI}/scans/${encodeURIComponent(scanId)}/recommendations`,
  );
}

/** `GET /ai/risk-priorities/{scan_id}` */
export function getRiskPriorities(scanId: string): Promise<AiRiskPriorities> {
  return apiRequest<AiRiskPriorities>(`${AI}/risk-priorities/${encodeURIComponent(scanId)}`);
}

/** `GET /ai/chat/sessions` — paged. */
export async function listChatSessions(
  params: PageParams = {},
  signal?: AbortSignal,
): Promise<Page<ChatSession>> {
  const limit = params.limit ?? 25;
  const payload = await apiRequest<Page<ChatSession> | ChatSession[]>(`${AI}/chat/sessions`, {
    query: { limit, cursor: params.cursor },
    signal,
  });
  return toPage(payload, limit);
}

/** `POST /ai/chat` — creates a session when `session_id` is omitted. */
export function sendChat(request: ChatRequest): Promise<ChatResponse> {
  return apiRequest<ChatResponse>(`${AI}/chat`, { method: 'POST', body: request });
}

/** `GET /ai/chat/{session_id}` — contract documents a bare `[ChatMessageOut]`. */
export async function getChatMessages(
  sessionId: string,
  signal?: AbortSignal,
): Promise<ChatMessage[]> {
  const payload = await apiRequest<ChatMessage[] | Page<ChatMessage>>(
    `${AI}/chat/${encodeURIComponent(sessionId)}`,
    { signal },
  );
  if (Array.isArray(payload)) return payload;
  return toPage(payload, 25).items;
}

/** `DELETE /ai/chat/{session_id}` → `204`. */
export function deleteChatSession(sessionId: string): Promise<void> {
  return apiRequest<void>(`${AI}/chat/${encodeURIComponent(sessionId)}`, { method: 'DELETE' });
}

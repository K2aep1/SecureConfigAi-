/**
 * URL safety helpers.
 *
 * Reference links and evidence URLs come from the API, so they are untrusted
 * input. Only `http:`/`https:` targets are ever rendered as a link — anything
 * else (`javascript:`, `data:`, `file:`, malformed input) is shown as plain text
 * instead. This is the one place that decision is made.
 */

const SAFE_PROTOCOLS = new Set(['http:', 'https:']);

export function safeExternalHref(url: string | null | undefined): string | null {
  if (!url) return null;
  const trimmed = url.trim();
  if (!trimmed) return null;
  try {
    const parsed = new URL(trimmed, window.location.origin);
    if (!SAFE_PROTOCOLS.has(parsed.protocol)) return null;
    return parsed.toString();
  } catch {
    return null;
  }
}

export function isSafeExternalUrl(url: string | null | undefined): boolean {
  return safeExternalHref(url) !== null;
}

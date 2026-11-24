/**
 * JSON parsing without `any`.
 *
 * The policy editor accepts JSON from a human, so the parsed result is validated
 * into the `JsonValue` union before it can reach the API client. `JSON.parse`
 * returns `any`; that value never escapes this module.
 */

import type { JsonObject, JsonValue } from '../types';

export type JsonParseResult =
  | { ok: true; value: JsonValue }
  | { ok: false; error: string };

function isJsonValue(value: unknown): value is JsonValue {
  if (value === null) return true;
  const type = typeof value;
  if (type === 'string' || type === 'number' || type === 'boolean') return true;
  if (Array.isArray(value)) return value.every(isJsonValue);
  if (type === 'object') {
    return Object.values(value as Record<string, unknown>).every(isJsonValue);
  }
  return false;
}

/** Parses text into `JsonValue`, reporting a readable error instead of throwing. */
export function tryParseJsonValue(text: string): JsonParseResult {
  const trimmed = text.trim();
  if (trimmed === '') return { ok: false, error: 'Enter a JSON value.' };
  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch (error) {
    return {
      ok: false,
      error: error instanceof Error ? `Invalid JSON: ${error.message}` : 'Invalid JSON.',
    };
  }
  if (!isJsonValue(parsed)) {
    return { ok: false, error: 'Only JSON values (object, array, string, number, boolean, null) are supported.' };
  }
  return { ok: true, value: parsed };
}

/** Convenience for callers that already hold an object. */
export function asJsonObject(value: JsonValue | undefined): JsonObject | undefined {
  if (value === undefined || value === null) return undefined;
  if (typeof value === 'object' && !Array.isArray(value)) return value;
  return undefined;
}

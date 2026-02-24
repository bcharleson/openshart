/**
 * @module webhook/validation
 * Strict input validation at webhook entry.
 * Validates required fields + types for every action before any tool call.
 */

import type {
  WebhookRequest,
  WebhookAction,
  ValidationIssue,
  StoreParams,
  SearchParams,
  GetParams,
  ForgetParams,
} from './types.js';

const VALID_ACTIONS: ReadonlySet<string> = new Set<WebhookAction>([
  'memory_store',
  'memory_search',
  'memory_get',
  'memory_forget',
]);

/**
 * Validate the top-level request envelope and action-specific params.
 * Returns an empty array when the request is valid.
 */
export function validateRequest(raw: unknown): ValidationIssue[] {
  const issues: ValidationIssue[] = [];

  if (raw === null || typeof raw !== 'object') {
    issues.push({ field: 'body', expected: 'object', received: String(typeof raw) });
    return issues;
  }

  const req = raw as Record<string, unknown>;

  // ── Top-level fields ──────────────────────────────────────

  if (typeof req['action'] !== 'string' || !VALID_ACTIONS.has(req['action'])) {
    issues.push({
      field: 'action',
      expected: 'one of: memory_store, memory_search, memory_get, memory_forget',
      received: String(req['action'] ?? 'undefined'),
    });
  }

  if (typeof req['request_id'] !== 'string' || req['request_id'].length === 0) {
    issues.push({
      field: 'request_id',
      expected: 'non-empty string',
      received: String(req['request_id'] ?? 'undefined'),
    });
  }

  if (req['idempotency_key'] !== undefined && typeof req['idempotency_key'] !== 'string') {
    issues.push({
      field: 'idempotency_key',
      expected: 'string | undefined',
      received: typeof req['idempotency_key'],
    });
  }

  if (req['params'] === null || typeof req['params'] !== 'object') {
    issues.push({ field: 'params', expected: 'object', received: String(typeof req['params']) });
    return issues;
  }

  // ── Action-specific validation ────────────────────────────

  if (typeof req['action'] === 'string' && VALID_ACTIONS.has(req['action'])) {
    const action = req['action'] as WebhookAction;
    const params = req['params'] as Record<string, unknown>;
    issues.push(...validateActionParams(action, params));
  }

  return issues;
}

function validateActionParams(action: WebhookAction, params: Record<string, unknown>): ValidationIssue[] {
  switch (action) {
    case 'memory_store':
      return validateStoreParams(params);
    case 'memory_search':
      return validateSearchParams(params);
    case 'memory_get':
      return validateGetParams(params);
    case 'memory_forget':
      return validateForgetParams(params);
  }
}

function validateStoreParams(p: Record<string, unknown>): ValidationIssue[] {
  const issues: ValidationIssue[] = [];
  if (typeof p['content'] !== 'string' || p['content'].length === 0) {
    issues.push({ field: 'params.content', expected: 'non-empty string', received: String(typeof p['content']) });
  }
  if (p['tags'] !== undefined && !Array.isArray(p['tags'])) {
    issues.push({ field: 'params.tags', expected: 'string[] | undefined', received: typeof p['tags'] });
  }
  if (Array.isArray(p['tags'])) {
    for (let i = 0; i < p['tags'].length; i++) {
      if (typeof p['tags'][i] !== 'string') {
        issues.push({ field: `params.tags[${i}]`, expected: 'string', received: typeof p['tags'][i] });
      }
    }
  }
  return issues;
}

function validateSearchParams(p: Record<string, unknown>): ValidationIssue[] {
  const issues: ValidationIssue[] = [];
  if (typeof p['query'] !== 'string') {
    issues.push({ field: 'params.query', expected: 'string', received: String(typeof p['query']) });
  }
  if (p['maxResults'] !== undefined && (typeof p['maxResults'] !== 'number' || !Number.isFinite(p['maxResults']) || p['maxResults'] < 1)) {
    issues.push({ field: 'params.maxResults', expected: 'positive number | undefined', received: String(p['maxResults']) });
  }
  if (p['tags'] !== undefined && !Array.isArray(p['tags'])) {
    issues.push({ field: 'params.tags', expected: 'string[] | undefined', received: typeof p['tags'] });
  }
  return issues;
}

function validateGetParams(p: Record<string, unknown>): ValidationIssue[] {
  const issues: ValidationIssue[] = [];
  if (typeof p['id'] !== 'string' || p['id'].length === 0) {
    issues.push({ field: 'params.id', expected: 'non-empty string', received: String(typeof p['id']) });
  }
  return issues;
}

function validateForgetParams(p: Record<string, unknown>): ValidationIssue[] {
  const issues: ValidationIssue[] = [];
  if (typeof p['id'] !== 'string' || p['id'].length === 0) {
    issues.push({ field: 'params.id', expected: 'non-empty string', received: String(typeof p['id']) });
  }
  return issues;
}

/**
 * Type guard: narrows a validated request to the typed WebhookRequest.
 */
export function asValidRequest(raw: unknown): WebhookRequest {
  const r = raw as Record<string, unknown>;
  return {
    action: r['action'] as WebhookRequest['action'],
    request_id: r['request_id'] as string,
    idempotency_key: r['idempotency_key'] as string | undefined,
    params: r['params'] as WebhookRequest['params'],
  };
}

// Re-export param types for consumer convenience
export type { StoreParams, SearchParams, GetParams, ForgetParams };

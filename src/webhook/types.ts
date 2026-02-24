/**
 * @module webhook/types
 * Strict contract types for the OpenShart webhook flow.
 *
 * Every request carries a request_id and optional idempotency_key.
 * Every response is a deterministic envelope with status, code, message,
 * request_id, data, and optional timing breakdown.
 */

// ─── Actions ──────────────────────────────────────────────────

export type WebhookAction =
  | 'memory_store'
  | 'memory_search'
  | 'memory_get'
  | 'memory_forget';

// ─── Per-action param shapes ──────────────────────────────────

export interface StoreParams {
  content: string;
  tags?: string[];
  metadata?: Record<string, unknown>;
}

export interface SearchParams {
  query: string;
  maxResults?: number;
  tags?: string[];
}

export interface GetParams {
  id: string;
}

export interface ForgetParams {
  id: string;
}

export type ActionParams = StoreParams | SearchParams | GetParams | ForgetParams;

// ─── Request ──────────────────────────────────────────────────

export interface WebhookRequest {
  action: WebhookAction;
  request_id: string;
  idempotency_key?: string;
  params: ActionParams;
}

// ─── Response status codes ────────────────────────────────────

export type ResponseStatus =
  | 'success'
  | 'no_result'
  | 'validation_error'
  | 'upstream_error';

export const STATUS_CODES: Record<ResponseStatus, number> = {
  success: 200,
  no_result: 204,
  validation_error: 400,
  upstream_error: 502,
};

// ─── Timing ───────────────────────────────────────────────────

export interface StepTiming {
  step: string;
  duration_ms: number;
}

export interface TimingInfo {
  total_ms: number;
  steps: StepTiming[];
}

// ─── Response envelope ────────────────────────────────────────

export interface WebhookResponse<T = unknown> {
  status: ResponseStatus;
  code: number;
  message: string;
  request_id: string;
  idempotency_key?: string;
  data: T;
  timing?: TimingInfo;
}

// ─── Validation error detail ──────────────────────────────────

export interface ValidationIssue {
  field: string;
  expected: string;
  received: string;
}

// ─── Logger interface (pluggable) ─────────────────────────────

export interface WebhookLogger {
  info(msg: string, ctx?: Record<string, unknown>): void;
  warn(msg: string, ctx?: Record<string, unknown>): void;
  error(msg: string, ctx?: Record<string, unknown>): void;
}

// ─── Handler config ───────────────────────────────────────────

export interface WebhookHandlerConfig {
  logger?: WebhookLogger;
}

/**
 * @module webhook/handler
 * OpenShart webhook handler with strict contracts.
 *
 * Responsibilities:
 * 1. Parse OpenShart tool returns as JSON string before mapping fields.
 * 2. Enforce input validation at webhook entry (required fields + types).
 * 3. Branch explicitly: success / no_result / validation_error / upstream_error.
 * 4. Propagate request_id and idempotency_key through every step.
 * 5. Return deterministic response envelopes.
 * 6. Log per-step latency and raw tool errors.
 */

import type { OpenShart } from '../core/openshart.js';
import { OpenShartNotFoundError, OpenShartExpiredError } from '../core/openshart.js';
import type { StoreResult, SearchResult, Memory, ForgetResult } from '../core/types.js';
import { memoryId } from '../core/types.js';
import { validateRequest, asValidRequest } from './validation.js';
import type {
  WebhookRequest,
  WebhookResponse,
  ResponseStatus,
  StepTiming,
  ValidationIssue,
  WebhookLogger,
  WebhookHandlerConfig,
  StoreParams,
  SearchParams,
  GetParams,
  ForgetParams,
} from './types.js';
import { STATUS_CODES } from './types.js';

// ─── Helpers ──────────────────────────────────────────────────

function hrMs(start: [number, number]): number {
  const [s, ns] = process.hrtime(start);
  return Math.round(s * 1000 + ns / 1_000_000);
}

function envelope<T>(
  status: ResponseStatus,
  message: string,
  data: T,
  requestId: string,
  idempotencyKey: string | undefined,
  steps: StepTiming[],
  totalStart: [number, number],
): WebhookResponse<T> {
  return {
    status,
    code: STATUS_CODES[status],
    message,
    request_id: requestId,
    ...(idempotencyKey !== undefined ? { idempotency_key: idempotencyKey } : {}),
    data,
    timing: {
      total_ms: hrMs(totalStart),
      steps,
    },
  };
}

/** Safely serialize a value into a JSON string, then parse it back for field mapping. */
function parseToolReturn<T>(raw: T): T {
  // Requirement 1: round-trip through JSON string to guarantee clean field mapping
  const json = JSON.stringify(raw);
  return JSON.parse(json) as T;
}

const NOOP_LOGGER: WebhookLogger = {
  info() {},
  warn() {},
  error() {},
};

// ─── Handler ──────────────────────────────────────────────────

export class WebhookHandler {
  private readonly shart: OpenShart;
  private readonly log: WebhookLogger;

  constructor(shart: OpenShart, config: WebhookHandlerConfig = {}) {
    this.shart = shart;
    this.log = config.logger ?? NOOP_LOGGER;
  }

  /**
   * Process a raw webhook request.
   * Always returns a deterministic response envelope — never throws.
   */
  async handle(raw: unknown): Promise<WebhookResponse> {
    const totalStart = process.hrtime();
    const steps: StepTiming[] = [];
    let requestId = '(unknown)';
    let idempotencyKey: string | undefined;

    try {
      // ── Step 1: Validation ──────────────────────────────────

      const valStart = process.hrtime();
      const issues = validateRequest(raw);
      steps.push({ step: 'validate', duration_ms: hrMs(valStart) });

      if (issues.length > 0) {
        // Attempt to extract request_id even from invalid payloads
        if (raw && typeof raw === 'object') {
          const r = raw as Record<string, unknown>;
          if (typeof r['request_id'] === 'string') requestId = r['request_id'];
          if (typeof r['idempotency_key'] === 'string') idempotencyKey = r['idempotency_key'];
        }
        this.log.warn('validation_error', { request_id: requestId, issues });
        return envelope<{ issues: ValidationIssue[] }>(
          'validation_error',
          `Validation failed: ${issues.map(i => i.field).join(', ')}`,
          { issues },
          requestId,
          idempotencyKey,
          steps,
          totalStart,
        );
      }

      const req: WebhookRequest = asValidRequest(raw);
      requestId = req.request_id;
      idempotencyKey = req.idempotency_key;

      this.log.info('request_start', { request_id: requestId, action: req.action, idempotency_key: idempotencyKey });

      // ── Step 2: Dispatch action ─────────────────────────────

      switch (req.action) {
        case 'memory_store':
          return await this.handleStore(req.params as StoreParams, requestId, idempotencyKey, steps, totalStart);
        case 'memory_search':
          return await this.handleSearch(req.params as SearchParams, requestId, idempotencyKey, steps, totalStart);
        case 'memory_get':
          return await this.handleGet(req.params as GetParams, requestId, idempotencyKey, steps, totalStart);
        case 'memory_forget':
          return await this.handleForget(req.params as ForgetParams, requestId, idempotencyKey, steps, totalStart);
      }
    } catch (err) {
      // Catch-all for truly unexpected errors
      const message = err instanceof Error ? err.message : String(err);
      this.log.error('unhandled_error', { request_id: requestId, error: message });
      return envelope(
        'upstream_error',
        `Unexpected error: ${message}`,
        { raw_error: message },
        requestId,
        idempotencyKey,
        steps,
        totalStart,
      );
    }
  }

  // ─── Action handlers ────────────────────────────────────────

  private async handleStore(
    params: StoreParams,
    requestId: string,
    idempotencyKey: string | undefined,
    steps: StepTiming[],
    totalStart: [number, number],
  ): Promise<WebhookResponse> {
    const toolStart = process.hrtime();
    let rawResult: StoreResult;
    try {
      rawResult = await this.shart.store(params.content, {
        tags: params.tags,
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      steps.push({ step: 'tool:memory_store', duration_ms: hrMs(toolStart) });
      this.log.error('tool_error', { request_id: requestId, tool: 'memory_store', error: message });
      return envelope('upstream_error', `Store failed: ${message}`, { raw_error: message }, requestId, idempotencyKey, steps, totalStart);
    }
    steps.push({ step: 'tool:memory_store', duration_ms: hrMs(toolStart) });

    // Requirement 1: parse tool return as JSON string before mapping
    const parseStart = process.hrtime();
    const parsed = parseToolReturn(rawResult);
    steps.push({ step: 'parse_response', duration_ms: hrMs(parseStart) });

    this.log.info('store_success', { request_id: requestId, memory_id: parsed.id, fragments: parsed.fragmentCount });

    return envelope(
      'success',
      'Memory stored successfully',
      {
        id: parsed.id,
        piiLevel: parsed.piiLevel,
        fragmentCount: parsed.fragmentCount,
        threshold: parsed.threshold,
        detectedPII: parsed.detectedPII,
      },
      requestId,
      idempotencyKey,
      steps,
      totalStart,
    );
  }

  private async handleSearch(
    params: SearchParams,
    requestId: string,
    idempotencyKey: string | undefined,
    steps: StepTiming[],
    totalStart: [number, number],
  ): Promise<WebhookResponse> {
    const toolStart = process.hrtime();
    let rawResult: SearchResult;
    try {
      rawResult = await this.shart.search(params.query, {
        limit: params.maxResults,
        tags: params.tags,
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      steps.push({ step: 'tool:memory_search', duration_ms: hrMs(toolStart) });
      this.log.error('tool_error', { request_id: requestId, tool: 'memory_search', error: message });
      return envelope('upstream_error', `Search failed: ${message}`, { raw_error: message }, requestId, idempotencyKey, steps, totalStart);
    }
    steps.push({ step: 'tool:memory_search', duration_ms: hrMs(toolStart) });

    const parseStart = process.hrtime();
    const parsed = parseToolReturn(rawResult);
    steps.push({ step: 'parse_response', duration_ms: hrMs(parseStart) });

    // Branch: no_result when search returns zero hits
    if (parsed.total === 0 || parsed.memories.length === 0) {
      this.log.info('search_no_result', { request_id: requestId, query: params.query });
      return envelope(
        'no_result',
        'Search returned no matching memories',
        { query: params.query, results: [], total: 0 },
        requestId,
        idempotencyKey,
        steps,
        totalStart,
      );
    }

    this.log.info('search_success', { request_id: requestId, total: parsed.total });

    return envelope(
      'success',
      `Found ${parsed.total} matching memories`,
      {
        results: parsed.memories.map(m => ({
          id: m.id,
          tags: m.tags,
          piiLevel: m.piiLevel,
          fragmentCount: m.fragmentCount,
        })),
        total: parsed.total,
        encrypted: parsed.encrypted,
      },
      requestId,
      idempotencyKey,
      steps,
      totalStart,
    );
  }

  private async handleGet(
    params: GetParams,
    requestId: string,
    idempotencyKey: string | undefined,
    steps: StepTiming[],
    totalStart: [number, number],
  ): Promise<WebhookResponse> {
    const mid = params.id.startsWith('openshart://')
      ? memoryId(params.id.replace(/^openshart:\/\//, ''))
      : memoryId(params.id);

    const toolStart = process.hrtime();
    let rawResult: Memory;
    try {
      rawResult = await this.shart.recall(mid);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      steps.push({ step: 'tool:memory_get', duration_ms: hrMs(toolStart) });

      if (err instanceof OpenShartNotFoundError) {
        this.log.info('get_not_found', { request_id: requestId, id: params.id });
        return envelope('no_result', `Memory not found: ${params.id}`, { id: params.id }, requestId, idempotencyKey, steps, totalStart);
      }
      if (err instanceof OpenShartExpiredError) {
        this.log.info('get_expired', { request_id: requestId, id: params.id });
        return envelope('no_result', `Memory expired: ${params.id}`, { id: params.id, expired: true }, requestId, idempotencyKey, steps, totalStart);
      }

      this.log.error('tool_error', { request_id: requestId, tool: 'memory_get', error: message });
      return envelope('upstream_error', `Get failed: ${message}`, { raw_error: message }, requestId, idempotencyKey, steps, totalStart);
    }
    steps.push({ step: 'tool:memory_get', duration_ms: hrMs(toolStart) });

    const parseStart = process.hrtime();
    const parsed = parseToolReturn(rawResult);
    steps.push({ step: 'parse_response', duration_ms: hrMs(parseStart) });

    this.log.info('get_success', { request_id: requestId, id: parsed.id });

    return envelope(
      'success',
      'Memory retrieved successfully',
      {
        id: parsed.id,
        content: parsed.content,
        tags: parsed.tags,
        piiLevel: parsed.piiLevel,
        createdAt: parsed.createdAt,
      },
      requestId,
      idempotencyKey,
      steps,
      totalStart,
    );
  }

  private async handleForget(
    params: ForgetParams,
    requestId: string,
    idempotencyKey: string | undefined,
    steps: StepTiming[],
    totalStart: [number, number],
  ): Promise<WebhookResponse> {
    const mid = params.id.startsWith('openshart://')
      ? memoryId(params.id.replace(/^openshart:\/\//, ''))
      : memoryId(params.id);

    const toolStart = process.hrtime();
    let rawResult: ForgetResult;
    try {
      rawResult = await this.shart.forget(mid);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      steps.push({ step: 'tool:memory_forget', duration_ms: hrMs(toolStart) });

      if (err instanceof OpenShartNotFoundError) {
        this.log.info('forget_not_found', { request_id: requestId, id: params.id });
        return envelope('no_result', `Memory not found: ${params.id}`, { id: params.id }, requestId, idempotencyKey, steps, totalStart);
      }

      this.log.error('tool_error', { request_id: requestId, tool: 'memory_forget', error: message });
      return envelope('upstream_error', `Forget failed: ${message}`, { raw_error: message }, requestId, idempotencyKey, steps, totalStart);
    }
    steps.push({ step: 'tool:memory_forget', duration_ms: hrMs(toolStart) });

    const parseStart = process.hrtime();
    const parsed = parseToolReturn(rawResult);
    steps.push({ step: 'parse_response', duration_ms: hrMs(parseStart) });

    this.log.info('forget_success', { request_id: requestId, id: parsed.memoryId, destroyed: parsed.fragmentsDestroyed });

    return envelope(
      'success',
      'Memory erased (GDPR Article 17)',
      {
        memoryId: parsed.memoryId,
        fragmentsDestroyed: parsed.fragmentsDestroyed,
        searchTokensPurged: parsed.searchTokensPurged,
      },
      requestId,
      idempotencyKey,
      steps,
      totalStart,
    );
  }
}

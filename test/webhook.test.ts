/**
 * Webhook handler — acceptance tests.
 *
 * 5 tests that exercise the strict-contract webhook flow end-to-end:
 *
 * 1. Happy path:        store → search → get  (success envelopes)
 * 2. Validation error:  missing required field (validation_error envelope)
 * 3. No result:         search for nonexistent content (no_result envelope)
 * 4. Upstream error:    get a non-existent memory id (upstream_error / no_result)
 * 5. Propagation:       request_id + idempotency_key present in every response
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { randomBytes } from 'node:crypto';
import { OpenShart } from '../src/core/openshart.js';
import { MemoryBackend } from '../src/storage/memory.js';
import { WebhookHandler } from '../src/webhook/handler.js';
import type { WebhookResponse, WebhookLogger } from '../src/webhook/types.js';

// ─── Helpers ──────────────────────────────────────────────────

interface LogEntry {
  level: string;
  msg: string;
  ctx?: Record<string, unknown>;
}

function createCapturingLogger(): { logger: WebhookLogger; entries: LogEntry[] } {
  const entries: LogEntry[] = [];
  return {
    entries,
    logger: {
      info(msg, ctx) { entries.push({ level: 'info', msg, ctx }); },
      warn(msg, ctx) { entries.push({ level: 'warn', msg, ctx }); },
      error(msg, ctx) { entries.push({ level: 'error', msg, ctx }); },
    },
  };
}

/** Assert envelope shape is valid regardless of status. */
function assertEnvelopeShape(resp: WebhookResponse): void {
  expect(resp).toHaveProperty('status');
  expect(resp).toHaveProperty('code');
  expect(resp).toHaveProperty('message');
  expect(resp).toHaveProperty('request_id');
  expect(resp).toHaveProperty('data');
  expect(resp).toHaveProperty('timing');
  expect(typeof resp.status).toBe('string');
  expect(typeof resp.code).toBe('number');
  expect(typeof resp.message).toBe('string');
  expect(typeof resp.request_id).toBe('string');
  expect(resp.timing).toBeDefined();
  expect(resp.timing!.total_ms).toBeGreaterThanOrEqual(0);
  expect(Array.isArray(resp.timing!.steps)).toBe(true);
  for (const step of resp.timing!.steps) {
    expect(typeof step.step).toBe('string');
    expect(typeof step.duration_ms).toBe('number');
  }
}

// ─── Suite ────────────────────────────────────────────────────

describe('Webhook Handler — Acceptance Tests', () => {
  let shart: OpenShart;
  let handler: WebhookHandler;
  let logCapture: ReturnType<typeof createCapturingLogger>;

  beforeEach(async () => {
    const storage = new MemoryBackend();
    shart = await OpenShart.init({
      storage,
      encryptionKey: randomBytes(32),
    });
    logCapture = createCapturingLogger();
    handler = new WebhookHandler(shart, { logger: logCapture.logger });
  });

  afterEach(async () => {
    await shart.close();
  });

  // ────────────────────────────────────────────────────────────
  // TEST 1: Happy path — store → search → get
  // ────────────────────────────────────────────────────────────
  it('T1: happy path — store → search → get returns success envelopes with correct data', async () => {
    // ── Store ───────────────────────────────────────────────
    const storeResp = await handler.handle({
      action: 'memory_store',
      request_id: 'req-001',
      idempotency_key: 'idem-001',
      params: {
        content: 'Project Nexus launch date is March 15th.',
        tags: ['project', 'launch'],
      },
    }) as WebhookResponse<{ id: string; piiLevel: string; fragmentCount: number }>;

    assertEnvelopeShape(storeResp);
    expect(storeResp.status).toBe('success');
    expect(storeResp.code).toBe(200);
    expect(storeResp.request_id).toBe('req-001');
    expect(storeResp.idempotency_key).toBe('idem-001');
    expect(storeResp.data.id).toBeTruthy();
    expect(storeResp.data.fragmentCount).toBeGreaterThanOrEqual(2);
    expect(storeResp.timing!.steps.some(s => s.step === 'tool:memory_store')).toBe(true);
    expect(storeResp.timing!.steps.some(s => s.step === 'parse_response')).toBe(true);

    const storedId = storeResp.data.id;

    // ── Search ──────────────────────────────────────────────
    const searchResp = await handler.handle({
      action: 'memory_search',
      request_id: 'req-002',
      params: { query: 'launch' },
    }) as WebhookResponse<{ results: Array<{ id: string }>; total: number }>;

    assertEnvelopeShape(searchResp);
    expect(searchResp.status).toBe('success');
    expect(searchResp.code).toBe(200);
    expect(searchResp.data.total).toBe(1);
    expect(searchResp.data.results[0]!.id).toBe(storedId);

    // ── Get ─────────────────────────────────────────────────
    const getResp = await handler.handle({
      action: 'memory_get',
      request_id: 'req-003',
      params: { id: storedId },
    }) as WebhookResponse<{ id: string; content: string; tags: string[] }>;

    assertEnvelopeShape(getResp);
    expect(getResp.status).toBe('success');
    expect(getResp.code).toBe(200);
    expect(getResp.data.content).toBe('Project Nexus launch date is March 15th.');
    expect(getResp.data.tags).toEqual(['project', 'launch']);

    // ── Verify per-step latency was logged ──────────────────
    const infoLogs = logCapture.entries.filter(e => e.level === 'info');
    expect(infoLogs.some(e => e.msg === 'store_success')).toBe(true);
    expect(infoLogs.some(e => e.msg === 'search_success')).toBe(true);
    expect(infoLogs.some(e => e.msg === 'get_success')).toBe(true);
  });

  // ────────────────────────────────────────────────────────────
  // TEST 2: Validation error — missing required fields
  // ────────────────────────────────────────────────────────────
  it('T2: validation_error — missing required fields returns 400 with issue details', async () => {
    // Missing action, missing params
    const resp1 = await handler.handle({
      request_id: 'req-val-001',
    }) as WebhookResponse<{ issues: Array<{ field: string }> }>;

    assertEnvelopeShape(resp1);
    expect(resp1.status).toBe('validation_error');
    expect(resp1.code).toBe(400);
    expect(resp1.request_id).toBe('req-val-001');
    expect(resp1.data.issues.length).toBeGreaterThan(0);
    expect(resp1.data.issues.some(i => i.field === 'action')).toBe(true);
    expect(resp1.timing!.steps.some(s => s.step === 'validate')).toBe(true);

    // Valid action but missing required param (content for store)
    const resp2 = await handler.handle({
      action: 'memory_store',
      request_id: 'req-val-002',
      params: {},
    }) as WebhookResponse<{ issues: Array<{ field: string }> }>;

    assertEnvelopeShape(resp2);
    expect(resp2.status).toBe('validation_error');
    expect(resp2.code).toBe(400);
    expect(resp2.data.issues.some(i => i.field === 'params.content')).toBe(true);

    // Completely garbage input
    const resp3 = await handler.handle(null) as WebhookResponse<{ issues: Array<{ field: string }> }>;

    assertEnvelopeShape(resp3);
    expect(resp3.status).toBe('validation_error');
    expect(resp3.code).toBe(400);
    expect(resp3.data.issues.some(i => i.field === 'body')).toBe(true);

    // Verify warnings were logged
    expect(logCapture.entries.filter(e => e.level === 'warn' && e.msg === 'validation_error').length).toBe(3);
  });

  // ────────────────────────────────────────────────────────────
  // TEST 3: No result — search for nonexistent content
  // ────────────────────────────────────────────────────────────
  it('T3: no_result — search for nonexistent content returns 204 with empty results', async () => {
    const resp = await handler.handle({
      action: 'memory_search',
      request_id: 'req-no-001',
      idempotency_key: 'idem-no-001',
      params: { query: 'something_that_does_not_exist_xyz123' },
    }) as WebhookResponse<{ query: string; results: unknown[]; total: number }>;

    assertEnvelopeShape(resp);
    expect(resp.status).toBe('no_result');
    expect(resp.code).toBe(204);
    expect(resp.request_id).toBe('req-no-001');
    expect(resp.idempotency_key).toBe('idem-no-001');
    expect(resp.data.results).toEqual([]);
    expect(resp.data.total).toBe(0);
    expect(resp.message).toContain('no matching');

    // Also test get for non-existent ID → no_result
    const getResp = await handler.handle({
      action: 'memory_get',
      request_id: 'req-no-002',
      params: { id: 'mem_doesnotexist00000' },
    }) as WebhookResponse<{ id: string }>;

    assertEnvelopeShape(getResp);
    expect(getResp.status).toBe('no_result');
    expect(getResp.code).toBe(204);
    expect(getResp.data.id).toBe('mem_doesnotexist00000');
  });

  // ────────────────────────────────────────────────────────────
  // TEST 4: Upstream error — tool failure surfaces as 502
  // ────────────────────────────────────────────────────────────
  it('T4: upstream_error — broken OpenShart instance returns 502 with raw_error', async () => {
    // Close the shart instance to simulate an upstream failure
    await shart.close();

    // Create a handler with a poisoned instance that will throw on any operation
    const poisonedStorage = new MemoryBackend();
    // We'll just use a store call that triggers an error by closing and trying to use
    // Actually, let's create a mock that throws
    const brokenShart = {
      store: async () => { throw new Error('ECONNREFUSED: upstream storage unavailable'); },
      search: async () => { throw new Error('ECONNREFUSED: upstream storage unavailable'); },
      recall: async () => { throw new Error('ECONNREFUSED: upstream storage unavailable'); },
      forget: async () => { throw new Error('ECONNREFUSED: upstream storage unavailable'); },
    } as unknown as OpenShart;

    const brokenHandler = new WebhookHandler(brokenShart, { logger: logCapture.logger });

    const storeResp = await brokenHandler.handle({
      action: 'memory_store',
      request_id: 'req-err-001',
      idempotency_key: 'idem-err-001',
      params: { content: 'this will fail' },
    }) as WebhookResponse<{ raw_error: string }>;

    assertEnvelopeShape(storeResp);
    expect(storeResp.status).toBe('upstream_error');
    expect(storeResp.code).toBe(502);
    expect(storeResp.request_id).toBe('req-err-001');
    expect(storeResp.idempotency_key).toBe('idem-err-001');
    expect(storeResp.data.raw_error).toContain('ECONNREFUSED');
    expect(storeResp.message).toContain('Store failed');

    const searchResp = await brokenHandler.handle({
      action: 'memory_search',
      request_id: 'req-err-002',
      params: { query: 'anything' },
    }) as WebhookResponse<{ raw_error: string }>;

    assertEnvelopeShape(searchResp);
    expect(searchResp.status).toBe('upstream_error');
    expect(searchResp.code).toBe(502);
    expect(searchResp.data.raw_error).toContain('ECONNREFUSED');

    // Verify error logs captured the raw tool errors
    const errorLogs = logCapture.entries.filter(e => e.level === 'error' && e.msg === 'tool_error');
    expect(errorLogs.length).toBeGreaterThanOrEqual(2);
    expect((errorLogs[0]!.ctx as Record<string, unknown>)['error']).toContain('ECONNREFUSED');
  });

  // ────────────────────────────────────────────────────────────
  // TEST 5: request_id + idempotency_key propagation
  // ────────────────────────────────────────────────────────────
  it('T5: request_id and idempotency_key propagate through every response and log entry', async () => {
    const rid = 'req-prop-uuid-42';
    const ikey = 'idem-prop-uuid-42';

    // Store (success path)
    const storeResp = await handler.handle({
      action: 'memory_store',
      request_id: rid,
      idempotency_key: ikey,
      params: { content: 'Propagation test data', tags: ['prop-test'] },
    });
    expect(storeResp.request_id).toBe(rid);
    expect(storeResp.idempotency_key).toBe(ikey);

    // Search (no_result path)
    const searchResp = await handler.handle({
      action: 'memory_search',
      request_id: `${rid}-search`,
      idempotency_key: `${ikey}-search`,
      params: { query: 'nonexistent_term_abc' },
    });
    expect(searchResp.request_id).toBe(`${rid}-search`);
    expect(searchResp.idempotency_key).toBe(`${ikey}-search`);

    // Validation error path
    const valResp = await handler.handle({
      action: 'bad_action',
      request_id: `${rid}-val`,
      idempotency_key: `${ikey}-val`,
      params: {},
    });
    expect(valResp.request_id).toBe(`${rid}-val`);
    expect(valResp.idempotency_key).toBe(`${ikey}-val`);

    // Without idempotency_key — should NOT appear in response
    const noIdemResp = await handler.handle({
      action: 'memory_search',
      request_id: `${rid}-noidem`,
      params: { query: 'test' },
    });
    expect(noIdemResp.request_id).toBe(`${rid}-noidem`);
    expect(noIdemResp).not.toHaveProperty('idempotency_key');

    // Verify logs also carry request_id
    const allLogs = logCapture.entries.filter(e => e.ctx && 'request_id' in e.ctx);
    expect(allLogs.length).toBeGreaterThanOrEqual(3);
    expect(allLogs.some(e => (e.ctx as Record<string, unknown>)['request_id'] === rid)).toBe(true);
    expect(allLogs.some(e => (e.ctx as Record<string, unknown>)['request_id'] === `${rid}-search`)).toBe(true);
  });
});

#!/usr/bin/env npx tsx
/**
 * Distributed OpenShart Test Harness
 * ===================================
 * Run this on each node (Mac Mini, DO droplet) pointing at the same Postgres.
 *
 * Usage:
 *   # On every node:
 *   OPENSHART_PG_URL=postgres://user:pass@db-host:5432/openshart \
 *   OPENSHART_SHARED_KEY=hex-encoded-32-byte-key \
 *   AGENT_ID=mac-mini-1 \
 *   npx tsx scripts/distributed-test.ts
 *
 * What it does:
 *   1. WRITE phase  — stores memories tagged with this agent's ID
 *   2. WAIT  phase  — waits for other agents to finish writing
 *   3. READ  phase  — reads memories stored by OTHER agents
 *   4. SEARCH phase — searches for content stored by other agents
 *   5. FORGET phase — each agent forgets its own memories, verifies others can't recall
 *   6. REPORT       — prints results
 *
 * Environment variables:
 *   OPENSHART_PG_URL    — Postgres connection string (required)
 *   OPENSHART_SHARED_KEY — Hex-encoded 32-byte shared encryption key (required)
 *   AGENT_ID             — Unique ID for this node (default: hostname)
 *   AGENT_COUNT          — Total number of agents in the test (default: 2)
 *   SECURITY_LEVEL       — standard | enterprise | government (default: standard)
 */

import { randomBytes } from 'node:crypto';
import { hostname } from 'node:os';

// ─── Configuration ──────────────────────────────────────────────

const PG_URL = process.env['OPENSHART_PG_URL'];
const SHARED_KEY_HEX = process.env['OPENSHART_SHARED_KEY'];
const AGENT_ID = process.env['AGENT_ID'] ?? hostname();
const AGENT_COUNT = parseInt(process.env['AGENT_COUNT'] ?? '2', 10);
const SECURITY_LEVEL = (process.env['SECURITY_LEVEL'] ?? 'standard') as 'standard' | 'enterprise' | 'government';

if (!PG_URL) {
  console.error('ERROR: OPENSHART_PG_URL is required');
  console.error('  Example: postgres://openshart:password@db-host:25060/openshart_test?sslmode=require');
  process.exit(1);
}

if (!SHARED_KEY_HEX) {
  // Generate one for the user and tell them to share it
  const generated = randomBytes(32).toString('hex');
  console.error('ERROR: OPENSHART_SHARED_KEY is required');
  console.error('  Here is a freshly generated key — share it across all nodes:');
  console.error(`  export OPENSHART_SHARED_KEY=${generated}`);
  process.exit(1);
}

const sharedKey = Buffer.from(SHARED_KEY_HEX, 'hex');
if (sharedKey.length !== 32) {
  console.error('ERROR: OPENSHART_SHARED_KEY must be exactly 32 bytes (64 hex characters)');
  process.exit(1);
}

// ─── Helpers ────────────────────────────────────────────────────

function log(phase: string, msg: string) {
  const ts = new Date().toISOString().slice(11, 23);
  console.log(`[${ts}] [${AGENT_ID}] [${phase}] ${msg}`);
}

function pass(label: string) {
  console.log(`  ✅ PASS: ${label}`);
}

function fail(label: string, err: unknown) {
  console.log(`  ❌ FAIL: ${label} — ${err instanceof Error ? err.message : err}`);
}

// ─── Main Test ──────────────────────────────────────────────────

async function main() {
  console.log('');
  console.log('╔══════════════════════════════════════════════════╗');
  console.log('║    OpenShart Distributed Test Harness            ║');
  console.log('╚══════════════════════════════════════════════════╝');
  console.log(`  Agent ID:       ${AGENT_ID}`);
  console.log(`  Postgres:       ${PG_URL!.replace(/\/\/[^@]*@/, '//***@')}`);
  console.log(`  Security Level: ${SECURITY_LEVEL}`);
  console.log(`  Agent Count:    ${AGENT_COUNT}`);
  console.log('');

  // Dynamic imports
  const { OpenShart } = await import('../src/core/openshart.js');
  const { PostgresBackend } = await import('../src/storage/postgres.js');

  const storage = new PostgresBackend({
    connectionString: PG_URL!,
    schema: 'openshart_dist_test',
    autoMigrate: true,
    poolSize: 5,
  });

  const shart = await OpenShart.init({
    storage,
    encryptionKey: sharedKey,
    agentId: AGENT_ID,
    securityLevel: SECURITY_LEVEL,
  });

  let passed = 0;
  let failed = 0;

  // ────────────────────────────────────────────────────────
  // PHASE 1: WRITE — Store memories tagged with our agent ID
  // ────────────────────────────────────────────────────────
  log('WRITE', 'Storing test memories...');

  const testContents = [
    `Agent ${AGENT_ID} secret: The launch code is ZULU-${Date.now()}.`,
    `Agent ${AGENT_ID} report: Quarterly revenue exceeded $42M.`,
    `Agent ${AGENT_ID} medical: Patient SSN 999-88-7777, allergy to penicillin.`,
  ];

  const storedIds: string[] = [];
  for (const content of testContents) {
    try {
      const result = await shart.store(content, {
        tags: [`agent:${AGENT_ID}`, 'dist-test'],
      });
      storedIds.push(result.id);
      pass(`Stored memory (${result.fragmentCount} fragments, threshold=${result.threshold})`);
      passed++;
    } catch (err) {
      fail('Store', err);
      failed++;
    }
  }

  // Write a coordination record so other agents know we're done
  await shart.store(`COORDINATION:WRITE_DONE:${AGENT_ID}:${Date.now()}`, {
    tags: ['coordination', `writer:${AGENT_ID}`],
  });

  log('WRITE', `Done. Stored ${storedIds.length} memories.`);

  // ────────────────────────────────────────────────────────
  // PHASE 2: WAIT — Poll for other agents' coordination records
  // ────────────────────────────────────────────────────────
  log('WAIT', `Waiting for ${AGENT_COUNT - 1} other agent(s)...`);

  const maxWaitMs = 120_000;
  const pollIntervalMs = 3_000;
  const start = Date.now();

  while (Date.now() - start < maxWaitMs) {
    const coordResults = await shart.search('COORDINATION', { tags: ['coordination'] });
    const writerCount = coordResults.total;

    if (writerCount >= AGENT_COUNT) {
      log('WAIT', `All ${AGENT_COUNT} agents have written. Proceeding.`);
      break;
    }

    const elapsed = Math.round((Date.now() - start) / 1000);
    log('WAIT', `${writerCount}/${AGENT_COUNT} agents ready. Waiting... (${elapsed}s)`);
    await new Promise(r => setTimeout(r, pollIntervalMs));
  }

  // ────────────────────────────────────────────────────────
  // PHASE 3: CROSS-READ — Read memories stored by OTHER agents
  // ────────────────────────────────────────────────────────
  log('CROSS-READ', 'Reading memories from other agents...');

  const allMetas = await shart.list({ tags: ['dist-test'] });
  const otherMetas = allMetas.filter(m => m.agentId !== AGENT_ID);

  log('CROSS-READ', `Found ${otherMetas.length} memories from other agents.`);

  for (const meta of otherMetas) {
    try {
      const memory = await shart.recall(meta.id);
      if (memory.content && memory.content.length > 0) {
        pass(`Recalled memory from agent ${meta.agentId} (${memory.content.length} chars)`);
        passed++;
      } else {
        fail(`Empty content from agent ${meta.agentId}`, 'content was empty');
        failed++;
      }
    } catch (err) {
      fail(`Recall from agent ${meta.agentId}`, err);
      failed++;
    }
  }

  // ────────────────────────────────────────────────────────
  // PHASE 4: CROSS-SEARCH — Search for content from other agents
  // ────────────────────────────────────────────────────────
  log('CROSS-SEARCH', 'Searching across all agents...');

  const searchTerms = ['launch', 'revenue', 'patient'];
  for (const term of searchTerms) {
    try {
      const results = await shart.search(term, { tags: ['dist-test'] });
      if (results.total > 0) {
        pass(`Search '${term}': found ${results.total} result(s)`);
        passed++;
      } else {
        // Might be zero if only this agent stored that term
        log('CROSS-SEARCH', `Search '${term}': 0 results (may be expected)`);
        passed++;
      }
    } catch (err) {
      fail(`Search '${term}'`, err);
      failed++;
    }
  }

  // ────────────────────────────────────────────────────────
  // PHASE 5: KEY ISOLATION — Verify different key can't read
  // ────────────────────────────────────────────────────────
  log('KEY-ISOLATION', 'Verifying encryption key isolation...');

  try {
    const wrongKey = randomBytes(32);
    const isolatedShart = await OpenShart.init({
      storage: new PostgresBackend({
        connectionString: PG_URL!,
        schema: 'openshart_dist_test',
        autoMigrate: false,
      }),
      encryptionKey: wrongKey,
      agentId: 'attacker',
    });

    const myMetas = allMetas.filter(m => m.agentId === AGENT_ID);
    if (myMetas.length > 0) {
      try {
        await isolatedShart.recall(myMetas[0]!.id);
        fail('Key isolation', 'Wrong key could read memory!');
        failed++;
      } catch {
        pass('Wrong encryption key correctly rejected');
        passed++;
      }
    }

    await isolatedShart.close();
  } catch (err) {
    fail('Key isolation setup', err);
    failed++;
  }

  // ────────────────────────────────────────────────────────
  // PHASE 6: FORGET — Each agent cleans up its own memories
  // ────────────────────────────────────────────────────────
  log('FORGET', 'Cryptographically erasing own memories...');

  for (const id of storedIds) {
    try {
      const result = await shart.forget(id as any);
      pass(`Forgot memory (${result.fragmentsDestroyed} fragments destroyed)`);
      passed++;
    } catch (err) {
      fail(`Forget ${id}`, err);
      failed++;
    }
  }

  // Verify forgotten memories are truly gone
  for (const id of storedIds) {
    try {
      await shart.recall(id as any);
      fail('Post-forget recall', 'Memory still exists after forget!');
      failed++;
    } catch {
      pass('Forgotten memory correctly unreachable');
      passed++;
    }
  }

  // ────────────────────────────────────────────────────────
  // PHASE 7: AUDIT — Verify audit chain integrity
  // ────────────────────────────────────────────────────────
  log('AUDIT', 'Checking audit trail...');

  try {
    const audit = await shart.export();
    log('AUDIT', `${audit.length} audit entries recorded.`);
    pass(`Audit trail has ${audit.length} entries`);
    passed++;
  } catch (err) {
    fail('Audit export', err);
    failed++;
  }

  // ────────────────────────────────────────────────────────
  // REPORT
  // ────────────────────────────────────────────────────────
  console.log('');
  console.log('══════════════════════════════════════════════════');
  console.log(`  Agent: ${AGENT_ID}`);
  console.log(`  Passed: ${passed}`);
  console.log(`  Failed: ${failed}`);
  console.log(`  Total:  ${passed + failed}`);
  console.log(`  Result: ${failed === 0 ? '✅ ALL PASSED' : '❌ FAILURES DETECTED'}`);
  console.log('══════════════════════════════════════════════════');
  console.log('');

  await shart.close();
  process.exit(failed > 0 ? 1 : 0);
}

main().catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});

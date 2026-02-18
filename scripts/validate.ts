#!/usr/bin/env npx tsx
/**
 * OpenShart Quick Validation
 * ==========================
 * Runs a fast end-to-end check of the core pipeline.
 * Use this after install to verify everything works.
 *
 * Usage:
 *   npx tsx scripts/validate.ts
 *   — or —
 *   npm run validate
 */

import { randomBytes } from 'node:crypto';

async function validate() {
  console.log('');
  console.log('OpenShart — Quick Validation');
  console.log('============================');
  console.log('');

  const { OpenShart } = await import('../src/core/openshart.js');
  const { MemoryBackend } = await import('../src/storage/memory.js');

  const key = randomBytes(32);
  const storage = new MemoryBackend();

  let passed = 0;
  let failed = 0;

  function check(label: string, ok: boolean, detail?: string) {
    if (ok) {
      console.log(`  ✅ ${label}`);
      passed++;
    } else {
      console.log(`  ❌ ${label}${detail ? ` — ${detail}` : ''}`);
      failed++;
    }
  }

  try {
    // 1. Initialize
    const shart = await OpenShart.init({ storage, encryptionKey: key });
    check('Initialize OpenShart', true);

    // 2. Store
    const content = 'The quick brown fox jumps over the lazy dog.';
    const result = await shart.store(content, { tags: ['test', 'validation'] });
    check('Store memory', !!result.id && result.fragmentCount >= 2);

    // 3. Recall
    const memory = await shart.recall(result.id);
    check('Recall memory', memory.content === content,
      memory.content !== content ? `got "${memory.content.slice(0, 40)}..."` : undefined);

    // 4. Search
    const searchResult = await shart.search('fox');
    check('Search (keyword)', searchResult.total === 1);

    const tagResult = await shart.search('', { tags: ['validation'] });
    check('Search (tag)', tagResult.total === 1);

    // 5. PII detection
    const piiResult = await shart.store('Patient SSN 123-45-6789, email test@example.com');
    check('PII auto-detection', piiResult.detectedPII.includes('SSN') && piiResult.detectedPII.includes('EMAIL'));
    check('PII increases fragmentation', piiResult.threshold >= 5);

    // Recall PII content
    const piiMemory = await shart.recall(piiResult.id);
    check('Recall PII content intact', piiMemory.content.includes('123-45-6789'));

    // 6. Key isolation
    const key2 = randomBytes(32);
    const shart2 = await OpenShart.init({ storage, encryptionKey: key2 });
    let isolated = false;
    try {
      await shart2.recall(result.id);
    } catch {
      isolated = true;
    }
    check('Key isolation (wrong key rejected)', isolated);
    // Note: don't close shart2 — it shares the MemoryBackend, and close() clears all data

    // 7. Forget (cryptographic erasure)
    const forgetResult = await shart.forget(result.id);
    check('Forget (cryptographic erasure)', forgetResult.fragmentsDestroyed >= 2);

    let forgotten = false;
    try {
      await shart.recall(result.id);
    } catch {
      forgotten = true;
    }
    check('Forgotten memory unreachable', forgotten);

    // 8. Audit chain
    const audit = await shart.export();
    check('Audit trail recorded', audit.length >= 4);

    // 9. Government security level
    const govShart = await OpenShart.init({
      storage: new MemoryBackend(),
      encryptionKey: randomBytes(32),
      securityLevel: 'government',
    });
    const govResult = await govShart.store('Classified briefing materials.');
    const govMemory = await govShart.recall(govResult.id);
    check('Government mode (ChainLock)', govMemory.content === 'Classified briefing materials.');
    await govShart.close();

    await shart.close();
  } catch (err) {
    console.log(`  ❌ FATAL: ${err instanceof Error ? err.message : err}`);
    failed++;
  }

  console.log('');
  console.log('---');
  console.log(`  Passed: ${passed}  Failed: ${failed}  Total: ${passed + failed}`);
  console.log(`  ${failed === 0 ? '✅ All checks passed — OpenShart is working correctly.' : '❌ Some checks failed.'}`);
  console.log('');

  process.exit(failed > 0 ? 1 : 0);
}

validate();

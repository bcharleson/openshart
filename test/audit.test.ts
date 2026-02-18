/**
 * Audit logging and hash chain integrity tests.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { randomBytes } from 'node:crypto';
import { OpenShart } from '../src/core/openshart.js';
import { MemoryBackend } from '../src/storage/memory.js';
import { AuditOperation } from '../src/core/types.js';

describe('Audit Logging', () => {
  let shart: OpenShart;

  beforeEach(async () => {
    shart = await OpenShart.init({
      storage: new MemoryBackend(),
      encryptionKey: randomBytes(32),
      agentId: 'test-agent',
    });
  });

  afterEach(async () => {
    await shart.close();
  });

  it('should log STORE operations', async () => {
    await shart.store('Audit this.');
    const entries = await shart.export({ operation: AuditOperation.STORE });
    expect(entries.length).toBeGreaterThanOrEqual(1);
    expect(entries[0]!.operation).toBe(AuditOperation.STORE);
    expect(entries[0]!.agentId).toBe('test-agent');
  });

  it('should log RECALL operations', async () => {
    const result = await shart.store('Recall me.');
    await shart.recall(result.id);

    const entries = await shart.export({ operation: AuditOperation.RECALL });
    expect(entries.length).toBeGreaterThanOrEqual(1);
  });

  it('should log SEARCH operations', async () => {
    await shart.store('Searchable content.', { tags: ['test'] });
    await shart.search('content');

    const entries = await shart.export({ operation: AuditOperation.SEARCH });
    expect(entries.length).toBeGreaterThanOrEqual(1);
  });

  it('should log FORGET operations', async () => {
    const result = await shart.store('Forget me.');
    await shart.forget(result.id);

    const entries = await shart.export({ operation: AuditOperation.FORGET });
    expect(entries.length).toBeGreaterThanOrEqual(1);
    expect(entries[0]!.details).toHaveProperty('method', 'dod_5220_22m_3pass');
  });

  it('should maintain a hash chain across operations', async () => {
    await shart.store('First.');
    await shart.store('Second.');
    await shart.store('Third.');

    const allEntries = await shart.export();
    // Sort chronologically (export returns reverse chronological)
    const sorted = [...allEntries].sort(
      (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime(),
    );

    // Each entry's previousHash should match the prior entry's hash
    for (let i = 1; i < sorted.length; i++) {
      expect(sorted[i]!.previousHash).toBe(sorted[i - 1]!.hash);
    }

    // First entry should reference genesis hash
    expect(sorted[0]!.previousHash).toBe('0'.repeat(64));
  });

  it('should verify audit chain integrity', async () => {
    await shart.store('Integrity check.');
    // Small delay ensures different timestamps so readAuditLog sort order is deterministic
    await new Promise(resolve => setTimeout(resolve, 10));
    await shart.store('Another entry.');

    const verification = await shart.verifyAuditChain();
    expect(verification.valid).toBe(true);
    expect(verification.entriesChecked).toBeGreaterThanOrEqual(2);
  });
});

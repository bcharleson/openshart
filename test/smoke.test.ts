/**
 * Smoke tests — verify the core store → recall → search → forget pipeline works.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { randomBytes } from 'node:crypto';
import { OpenShart } from '../src/core/openshart.js';
import { MemoryBackend } from '../src/storage/memory.js';
import type { MemoryId } from '../src/core/types.js';

describe('OpenShart — Smoke Tests', () => {
  let shart: OpenShart;
  let storage: MemoryBackend;
  const key = randomBytes(32);

  beforeEach(async () => {
    storage = new MemoryBackend();
    shart = await OpenShart.init({
      storage,
      encryptionKey: key,
    });
  });

  afterEach(async () => {
    await shart.close();
  });

  it('should store and recall a simple memory', async () => {
    const content = 'The secret launch code is ALPHA-BRAVO-7.';
    const result = await shart.store(content, { tags: ['secret', 'launch'] });

    expect(result.id).toBeTruthy();
    expect(result.fragmentCount).toBeGreaterThanOrEqual(2);
    expect(result.threshold).toBeGreaterThanOrEqual(2);

    const memory = await shart.recall(result.id);
    expect(memory.content).toBe(content);
    expect(memory.tags).toEqual(['secret', 'launch']);
  });

  it('should store and recall multiple memories independently', async () => {
    const contents = [
      'First memory: project alpha details.',
      'Second memory: budget projections for Q3.',
      'Third memory: personnel roster update.',
    ];

    const ids: MemoryId[] = [];
    for (const content of contents) {
      const result = await shart.store(content);
      ids.push(result.id);
    }

    // Recall each and verify isolation
    for (let i = 0; i < contents.length; i++) {
      const memory = await shart.recall(ids[i]!);
      expect(memory.content).toBe(contents[i]);
    }
  });

  it('should search memories by keyword without decrypting', async () => {
    await shart.store('The patient has a severe allergy to penicillin.', {
      tags: ['medical'],
    });
    await shart.store('Quarterly revenue exceeded expectations by 15%.', {
      tags: ['finance'],
    });

    const medicalResults = await shart.search('allergy');
    expect(medicalResults.total).toBe(1);
    expect(medicalResults.encrypted).toBe(true);

    const financeResults = await shart.search('revenue');
    expect(financeResults.total).toBe(1);
  });

  it('should search by tag', async () => {
    await shart.store('Secret project details.', { tags: ['project-x'] });
    await shart.store('Unrelated memo.', { tags: ['memo'] });

    const results = await shart.search('', { tags: ['project-x'] });
    expect(results.total).toBe(1);
  });

  it('should forget a memory (cryptographic erasure)', async () => {
    const result = await shart.store('Delete me securely.');
    const forgetResult = await shart.forget(result.id);

    expect(forgetResult.fragmentsDestroyed).toBeGreaterThan(0);
    expect(forgetResult.memoryId).toBe(result.id);

    // Should not be recallable
    await expect(shart.recall(result.id)).rejects.toThrow('not found');
  });

  it('should list memories without exposing content', async () => {
    await shart.store('Memory one.', { tags: ['a'] });
    await shart.store('Memory two.', { tags: ['b'] });

    const metas = await shart.list();
    expect(metas.length).toBe(2);

    // Meta should NOT contain content
    for (const meta of metas) {
      expect(meta).not.toHaveProperty('content');
      expect(meta.id).toBeTruthy();
      expect(meta.fragmentCount).toBeGreaterThan(0);
    }
  });

  it('should handle large content correctly', async () => {
    // 50KB of content
    const largeContent = 'X'.repeat(50_000);
    const result = await shart.store(largeContent);
    const memory = await shart.recall(result.id);
    expect(memory.content).toBe(largeContent);
  });

  it('should handle unicode content', async () => {
    const content = '机密文件：绝密等级。 🔐 Données classifiées. Geheime Daten.';
    const result = await shart.store(content);
    const memory = await shart.recall(result.id);
    expect(memory.content).toBe(content);
  });

  it('should throw on recalling non-existent memory', async () => {
    await expect(
      shart.recall('mem_doesnotexist0000' as MemoryId),
    ).rejects.toThrow('not found');
  });
});

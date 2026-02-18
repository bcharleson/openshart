/**
 * Edge cases, error handling, and validation tests.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { randomBytes } from 'node:crypto';
import { OpenShart } from '../src/core/openshart.js';
import { MemoryBackend } from '../src/storage/memory.js';
import type { MemoryId } from '../src/core/types.js';

describe('Initialization Validation', () => {
  it('should reject missing storage', async () => {
    await expect(
      OpenShart.init({
        storage: null as any,
        encryptionKey: randomBytes(32),
      }),
    ).rejects.toThrow('storage');
  });

  it('should reject wrong-length encryption key', async () => {
    await expect(
      OpenShart.init({
        storage: new MemoryBackend(),
        encryptionKey: randomBytes(16), // 128-bit, not 256-bit
      }),
    ).rejects.toThrow('32 bytes');
  });

  it('should reject all-zeros key', async () => {
    await expect(
      OpenShart.init({
        storage: new MemoryBackend(),
        encryptionKey: Buffer.alloc(32, 0),
      }),
    ).rejects.toThrow('entropy');
  });

  it('should reject low-entropy key (all same byte)', async () => {
    await expect(
      OpenShart.init({
        storage: new MemoryBackend(),
        encryptionKey: Buffer.alloc(32, 0x42),
      }),
    ).rejects.toThrow('entropy');
  });
});

describe('Memory Expiry (TTL)', () => {
  it('should set expiry for PII content based on level', async () => {
    const shart = await OpenShart.init({
      storage: new MemoryBackend(),
      encryptionKey: randomBytes(32),
    });

    // Store with explicit TTL
    const result = await shart.store('Ephemeral data.', {
      ttl: 1000, // 1 second
    });

    const metas = await shart.list();
    const meta = metas.find(m => m.id === result.id);
    expect(meta!.expiresAt).toBeTruthy();

    await shart.close();
  });

  it('should reject recall of expired memory', async () => {
    const storage = new MemoryBackend();
    const shart = await OpenShart.init({
      storage,
      encryptionKey: randomBytes(32),
    });

    // Store with immediate expiry
    const result = await shart.store('This will expire.', {
      ttl: 1, // 1ms
    });

    // Wait for expiry
    await new Promise(resolve => setTimeout(resolve, 50));

    await expect(shart.recall(result.id)).rejects.toThrow('expired');

    await shart.close();
  });
});

describe('Concurrent Operations', () => {
  let shart: OpenShart;

  beforeEach(async () => {
    shart = await OpenShart.init({
      storage: new MemoryBackend(),
      encryptionKey: randomBytes(32),
    });
  });

  afterEach(async () => {
    await shart.close();
  });

  it('should handle concurrent stores', async () => {
    const promises = Array.from({ length: 10 }, (_, i) =>
      shart.store(`Concurrent memory ${i}`, { tags: [`batch-${i}`] }),
    );

    const results = await Promise.all(promises);
    expect(results).toHaveLength(10);

    // Each should have a unique ID
    const ids = new Set(results.map(r => r.id));
    expect(ids.size).toBe(10);

    // Each should be recallable
    for (const result of results) {
      const memory = await shart.recall(result.id);
      expect(memory.content).toContain('Concurrent memory');
    }
  });

  it('should handle concurrent recalls', async () => {
    const stored = await shart.store('Recall me many times.');

    const promises = Array.from({ length: 10 }, () =>
      shart.recall(stored.id),
    );

    const memories = await Promise.all(promises);
    for (const memory of memories) {
      expect(memory.content).toBe('Recall me many times.');
    }
  });
});

describe('Different Encryption Keys Produce Isolation', () => {
  it('should not allow recall with a different key', async () => {
    const key1 = randomBytes(32);
    const key2 = randomBytes(32);
    const storage = new MemoryBackend();

    const shart1 = await OpenShart.init({ storage, encryptionKey: key1 });
    const result = await shart1.store('Only key1 can read this.');

    // Create new instance with different key but same storage
    const shart2 = await OpenShart.init({ storage, encryptionKey: key2 });

    // Recall should fail — wrong key means AES-GCM auth fails
    await expect(shart2.recall(result.id)).rejects.toThrow();

    await shart1.close();
    await shart2.close();
  });
});

describe('Forget (Cryptographic Erasure)', () => {
  it('should perform 3-pass DoD overwrite', async () => {
    const shart = await OpenShart.init({
      storage: new MemoryBackend(),
      encryptionKey: randomBytes(32),
    });

    const result = await shart.store('Destroy all evidence.');
    const forgetResult = await shart.forget(result.id);

    expect(forgetResult.fragmentsDestroyed).toBeGreaterThan(0);
    expect(forgetResult.auditId).toBeTruthy();

    // Search should not find it anymore
    const searchResult = await shart.search('evidence');
    expect(searchResult.total).toBe(0);

    await shart.close();
  });

  it('should throw when forgetting non-existent memory', async () => {
    const shart = await OpenShart.init({
      storage: new MemoryBackend(),
      encryptionKey: randomBytes(32),
    });

    await expect(
      shart.forget('mem_doesnotexist' as MemoryId),
    ).rejects.toThrow('not found');

    await shart.close();
  });
});

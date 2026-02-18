/**
 * Security level tests — standard, enterprise, government, classified.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { randomBytes } from 'node:crypto';
import { OpenShart } from '../src/core/openshart.js';
import { MemoryBackend } from '../src/storage/memory.js';
import { Classification } from '../src/hierarchy/classification.js';

describe('Security Levels', () => {
  describe('standard', () => {
    let shart: OpenShart;

    beforeEach(async () => {
      shart = await OpenShart.init({
        storage: new MemoryBackend(),
        encryptionKey: randomBytes(32),
        securityLevel: 'standard',
      });
    });

    afterEach(async () => {
      await shart.close();
    });

    it('should store and recall normally', async () => {
      const result = await shart.store('Standard security content.');
      const memory = await shart.recall(result.id);
      expect(memory.content).toBe('Standard security content.');
    });

    it('should report standard security level', () => {
      expect(shart.getSecurityLevel()).toBe('standard');
    });
  });

  describe('enterprise', () => {
    let shart: OpenShart;

    beforeEach(async () => {
      shart = await OpenShart.init({
        storage: new MemoryBackend(),
        encryptionKey: randomBytes(32),
        securityLevel: 'enterprise',
      });
    });

    afterEach(async () => {
      await shart.close();
    });

    it('should store and recall at enterprise level', async () => {
      const result = await shart.store('Enterprise security content.');
      const memory = await shart.recall(result.id);
      expect(memory.content).toBe('Enterprise security content.');
    });

    it('should reject weak encryption keys', async () => {
      // All-zeros key should fail entropy validation
      const weakKey = Buffer.alloc(32, 0);
      await expect(
        OpenShart.init({
          storage: new MemoryBackend(),
          encryptionKey: weakKey,
          securityLevel: 'enterprise',
        }),
      ).rejects.toThrow();
    });
  });

  describe('government', () => {
    let shart: OpenShart;

    beforeEach(async () => {
      shart = await OpenShart.init({
        storage: new MemoryBackend(),
        encryptionKey: randomBytes(32),
        securityLevel: 'government',
      });
    });

    afterEach(async () => {
      await shart.close();
    });

    it('should store and recall with ChainLock protocol', async () => {
      const result = await shart.store('Government classified content.');
      const memory = await shart.recall(result.id);
      expect(memory.content).toBe('Government classified content.');
    });

    it('should enable ChainLock at government level', () => {
      expect(shart.getSecurityLevel()).toBe('government');
      const chainLock = shart.getChainLock();
      expect(chainLock).toBeDefined();
    });
  });

  describe('classified with government classification', () => {
    let shart: OpenShart;

    beforeEach(async () => {
      shart = await OpenShart.init({
        storage: new MemoryBackend(),
        encryptionKey: randomBytes(32),
        securityLevel: 'classified',
        clearance: {
          maxClassification: Classification.TOP_SECRET,
          compartments: [{ compartment: 'COMINT' as any, granted: new Date().toISOString(), authority: 'test' }],
        },
      });
    });

    afterEach(async () => {
      await shart.close();
    });

    it('should store TOP_SECRET-classified content with increased fragmentation', async () => {
      const result = await shart.store('Eyes only: satellite imagery coordinates.', {
        classification: Classification.TOP_SECRET,
        tags: ['intel'],
      });

      // SECRET+ bumps fragmentation: threshold >= 5, fragments >= 8
      expect(result.threshold).toBeGreaterThanOrEqual(5);
      expect(result.fragmentCount).toBeGreaterThanOrEqual(8);
    });

    it('should recall classified content correctly', async () => {
      const content = 'TOP SECRET: Agent extraction plan for Operation Nightfall.';
      const result = await shart.store(content, {
        classification: Classification.TOP_SECRET,
      });

      const memory = await shart.recall(result.id);
      expect(memory.content).toBe(content);
    });
  });
});

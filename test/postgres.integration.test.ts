/**
 * Postgres integration tests.
 *
 * These tests require a running Postgres instance.
 * Set OPENSHART_PG_URL to run them:
 *
 *   OPENSHART_PG_URL=postgres://user:pass@localhost:5432/openshart_test npx vitest run test/postgres.integration.test.ts
 *
 * Skipped automatically if OPENSHART_PG_URL is not set.
 */
import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { randomBytes } from 'node:crypto';

const PG_URL = process.env['OPENSHART_PG_URL'];

// Conditionally import — pg may not be installed
const loadModules = async () => {
  const { OpenShart } = await import('../src/core/openshart.js');
  const { PostgresBackend } = await import('../src/storage/postgres.js');
  return { OpenShart, PostgresBackend };
};

describe.skipIf(!PG_URL)('Postgres Integration', () => {
  let OpenShart: any;
  let PostgresBackend: any;
  let storage: any;
  let shart: any;
  const key = randomBytes(32);

  beforeAll(async () => {
    const mods = await loadModules();
    OpenShart = mods.OpenShart;
    PostgresBackend = mods.PostgresBackend;

    storage = new PostgresBackend({
      connectionString: PG_URL!,
      schema: 'openshart_test',
      autoMigrate: true,
    });

    shart = await OpenShart.init({
      storage,
      encryptionKey: key,
      agentId: 'integration-test',
    });
  });

  afterAll(async () => {
    // Clean up test schema
    if (storage?.pool) {
      try {
        await storage.pool.query('DROP SCHEMA IF EXISTS openshart_test CASCADE');
      } catch { /* ignore */ }
    }
    await shart?.close();
  });

  it('should store and recall through Postgres', async () => {
    const content = 'Postgres integration: store and recall works.';
    const result = await shart.store(content, { tags: ['pg-test'] });

    expect(result.id).toBeTruthy();
    expect(result.fragmentCount).toBeGreaterThanOrEqual(2);

    const memory = await shart.recall(result.id);
    expect(memory.content).toBe(content);
  });

  it('should search through Postgres', async () => {
    await shart.store('The classified satellite coordinates are encrypted.', {
      tags: ['intel'],
    });

    const results = await shart.search('satellite');
    expect(results.total).toBeGreaterThanOrEqual(1);
    expect(results.encrypted).toBe(true);
  });

  it('should forget through Postgres (cryptographic erasure)', async () => {
    const result = await shart.store('Delete this from Postgres.');
    await shart.forget(result.id);

    await expect(shart.recall(result.id)).rejects.toThrow('not found');
  });

  it('should handle PII-heavy content through Postgres', async () => {
    const content = 'Patient Jane Doe, SSN 111-22-3333, email jane@hospital.com';
    const result = await shart.store(content);

    expect(result.detectedPII).toContain('SSN');
    expect(result.threshold).toBeGreaterThanOrEqual(5);

    const memory = await shart.recall(result.id);
    expect(memory.content).toBe(content);
  });

  it('should persist fragments as BYTEA (binary)', async () => {
    // Store content with binary-unfriendly characters
    const content = 'Binary test: \x00\x01\x02 null bytes and unicode 日本語';
    const result = await shart.store(content);
    const memory = await shart.recall(result.id);
    expect(memory.content).toBe(content);
  });

  it('should isolate memories between different encryption keys', async () => {
    const key2 = randomBytes(32);
    const shart2 = await OpenShart.init({
      storage: new PostgresBackend({
        connectionString: PG_URL!,
        schema: 'openshart_test',
        autoMigrate: false,
      }),
      encryptionKey: key2,
      agentId: 'different-agent',
    });

    const result = await shart.store('Only key1 can read this via Postgres.');

    // Different key = AES-GCM auth failure
    await expect(shart2.recall(result.id)).rejects.toThrow();

    await shart2.close();
  });
});

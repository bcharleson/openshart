/**
 * Cryptography tests — Shamir's Secret Sharing, AES-256-GCM, key derivation.
 */
import { describe, it, expect } from 'vitest';
import { randomBytes } from 'node:crypto';
import { split, reconstruct } from '../src/fragments/shard.js';
import {
  aesEncrypt,
  aesDecrypt,
  deriveFragmentKey,
  deriveSearchKey,
} from '../src/fragments/encrypt.js';
import { fragmentContent, reconstructContent } from '../src/fragments/fragment-engine.js';
import { memoryId } from '../src/core/types.js';

describe('Shamir Secret Sharing — GF(2^8)', () => {
  it('should split and reconstruct with exact threshold', () => {
    const secret = Buffer.from('hello world');
    const shares = split(secret, 3, 5);

    expect(shares).toHaveLength(5);

    // Reconstruct with exactly k=3 shares
    const recovered = reconstruct(shares.slice(0, 3));
    expect(recovered.toString('utf-8')).toBe('hello world');
  });

  it('should reconstruct from any k-of-n combination', () => {
    const secret = Buffer.from('any subset works');
    const shares = split(secret, 3, 5);

    // Try different combinations of 3 shares
    const combos = [
      [0, 1, 2],
      [0, 1, 4],
      [0, 3, 4],
      [1, 2, 3],
      [2, 3, 4],
    ];

    for (const combo of combos) {
      const subset = combo.map(i => shares[i]!);
      const recovered = reconstruct(subset);
      expect(recovered.toString('utf-8')).toBe('any subset works');
    }
  });

  it('should fail with fewer than threshold shares', () => {
    const secret = Buffer.from('need more shares');
    const shares = split(secret, 4, 6);

    // Only 2 shares — wrong reconstruction
    const recovered = reconstruct(shares.slice(0, 2));
    // With insufficient shares, Shamir produces garbage (not the original)
    expect(recovered.toString('utf-8')).not.toBe('need more shares');
  });

  it('should handle binary data', () => {
    const secret = randomBytes(128);
    const shares = split(secret, 3, 5);
    const recovered = reconstruct(shares.slice(0, 3));
    expect(Buffer.compare(recovered, secret)).toBe(0);
  });

  it('should reject invalid parameters', () => {
    const secret = Buffer.from('test');
    expect(() => split(secret, 1, 3)).toThrow();  // k < 2
    expect(() => split(secret, 4, 3)).toThrow();  // n < k
    expect(() => split(secret, 2, 256)).toThrow(); // n > 255
    expect(() => split(Buffer.alloc(0), 2, 3)).toThrow(); // empty
  });
});

describe('AES-256-GCM Encryption', () => {
  it('should encrypt and decrypt correctly', () => {
    const key = randomBytes(32);
    const plaintext = Buffer.from('top secret data');

    const { ciphertext, iv, authTag } = aesEncrypt(plaintext, key);
    const decrypted = aesDecrypt(ciphertext, key, iv, authTag);

    expect(decrypted.toString('utf-8')).toBe('top secret data');
  });

  it('should produce unique ciphertexts for same plaintext (random IV)', () => {
    const key = randomBytes(32);
    const plaintext = Buffer.from('same data');

    const enc1 = aesEncrypt(plaintext, key);
    const enc2 = aesEncrypt(plaintext, key);

    // Different IVs → different ciphertexts
    expect(Buffer.compare(enc1.iv, enc2.iv)).not.toBe(0);
    expect(Buffer.compare(enc1.ciphertext, enc2.ciphertext)).not.toBe(0);
  });

  it('should detect tampered ciphertext', () => {
    const key = randomBytes(32);
    const { ciphertext, iv, authTag } = aesEncrypt(Buffer.from('data'), key);

    // Tamper with ciphertext
    ciphertext[0] = ciphertext[0]! ^ 0xff;
    expect(() => aesDecrypt(ciphertext, key, iv, authTag)).toThrow();
  });

  it('should detect tampered auth tag', () => {
    const key = randomBytes(32);
    const { ciphertext, iv, authTag } = aesEncrypt(Buffer.from('data'), key);

    // Tamper with auth tag
    authTag[0] = authTag[0]! ^ 0xff;
    expect(() => aesDecrypt(ciphertext, key, iv, authTag)).toThrow();
  });

  it('should fail with wrong key', () => {
    const key1 = randomBytes(32);
    const key2 = randomBytes(32);
    const { ciphertext, iv, authTag } = aesEncrypt(Buffer.from('data'), key1);

    expect(() => aesDecrypt(ciphertext, key2, iv, authTag)).toThrow();
  });
});

describe('Key Derivation (HKDF)', () => {
  it('should derive different keys for different fragments', async () => {
    const master = randomBytes(32);
    const id = 'mem_test123';

    const key1 = await deriveFragmentKey(master, id, 1);
    const key2 = await deriveFragmentKey(master, id, 2);

    expect(key1.length).toBe(32);
    expect(key2.length).toBe(32);
    expect(Buffer.compare(key1, key2)).not.toBe(0);
  });

  it('should derive different keys for different memories', async () => {
    const master = randomBytes(32);

    const key1 = await deriveFragmentKey(master, 'mem_a', 1);
    const key2 = await deriveFragmentKey(master, 'mem_b', 1);

    expect(Buffer.compare(key1, key2)).not.toBe(0);
  });

  it('should derive deterministic keys', async () => {
    const master = randomBytes(32);

    const key1 = await deriveFragmentKey(master, 'mem_x', 5);
    const key2 = await deriveFragmentKey(master, 'mem_x', 5);

    expect(Buffer.compare(key1, key2)).toBe(0);
  });

  it('should derive search key from master key', async () => {
    const master = randomBytes(32);
    const searchKey = await deriveSearchKey(master);

    expect(searchKey.length).toBe(32);
    expect(Buffer.compare(searchKey, master)).not.toBe(0);
  });
});

describe('Fragment Engine — End-to-End', () => {
  it('should fragment and reconstruct content', async () => {
    const master = randomBytes(32);
    const id = memoryId('mem_fragtest001');
    const content = 'This is the secret message that gets split into fragments.';

    const fragments = await fragmentContent(content, id, master, {
      threshold: 3,
      totalShares: 5,
      slots: 5,
    });

    expect(fragments).toHaveLength(5);
    expect(fragments[0]!.memoryId).toBe(id);

    // Reconstruct from first 3 fragments (threshold)
    const recovered = await reconstructContent(fragments.slice(0, 3), master);
    expect(recovered).toBe(content);
  });

  it('should reconstruct from any subset meeting threshold', async () => {
    const master = randomBytes(32);
    const id = memoryId('mem_subsettest');
    const content = 'Reconstruct from any 3 of 5.';

    const fragments = await fragmentContent(content, id, master, {
      threshold: 3,
      totalShares: 5,
      slots: 5,
    });

    // Try last 3 fragments
    const recovered = await reconstructContent(fragments.slice(2, 5), master);
    expect(recovered).toBe(content);
  });

  it('should fail reconstruction with wrong master key', async () => {
    const master1 = randomBytes(32);
    const master2 = randomBytes(32);
    const id = memoryId('mem_wrongkey');
    const content = 'Wrong key should fail.';

    const fragments = await fragmentContent(content, id, master1, {
      threshold: 2,
      totalShares: 3,
      slots: 3,
    });

    // Trying with wrong key should throw (AES-GCM auth failure)
    await expect(
      reconstructContent(fragments.slice(0, 2), master2),
    ).rejects.toThrow();
  });
});

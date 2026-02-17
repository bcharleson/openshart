/**
 * @module chainlock/sequence
 * Cryptographically random sequence generation for ChainLock protocol.
 * Fragments must be decrypted in a specific order — the sequence defines that order.
 */

import { randomBytes, timingSafeEqual } from 'node:crypto';
import { aesEncrypt, aesDecrypt, deriveFragmentKey } from '../fragments/encrypt.js';

/** An encrypted sequence defining fragment decryption order */
export interface EncryptedSequence {
  /** Encrypted sequence data */
  ciphertext: Buffer;
  /** AES-GCM IV */
  iv: Buffer;
  /** AES-GCM auth tag */
  authTag: Buffer;
  /** Sequence version (incremented on rotation) */
  version: number;
  /** Creation timestamp */
  createdAt: string;
}

/**
 * Generate a cryptographically random ordering of fragment indices.
 * Uses Fisher-Yates shuffle with crypto.randomBytes for unbiased randomness.
 *
 * @param fragmentCount - Number of fragments to sequence
 * @returns Random permutation of indices [0, fragmentCount)
 */
export function generateSequence(fragmentCount: number): number[] {
  if (fragmentCount < 1) throw new Error('Fragment count must be >= 1');

  const indices = Array.from({ length: fragmentCount }, (_, i) => i);

  // Fisher-Yates shuffle with cryptographic randomness
  for (let i = indices.length - 1; i > 0; i--) {
    // Generate unbiased random index in [0, i]
    const rand = randomBytes(4).readUInt32BE(0);
    const j = rand % (i + 1);
    [indices[i], indices[j]] = [indices[j]!, indices[i]!];
  }

  return indices;
}

/**
 * Encrypt a sequence for storage.
 * The sequence itself is sensitive — knowing the order is half the attack.
 */
export async function encryptSequence(
  sequence: number[],
  masterKey: Buffer,
  memoryId: string,
  version: number,
): Promise<EncryptedSequence> {
  const key = await deriveFragmentKey(masterKey, `chainlock-seq-${memoryId}`, version);
  const plaintext = Buffer.from(JSON.stringify(sequence), 'utf-8');
  const { ciphertext, iv, authTag } = aesEncrypt(plaintext, key);

  return {
    ciphertext,
    iv,
    authTag,
    version,
    createdAt: new Date().toISOString(),
  };
}

/**
 * Decrypt a stored sequence.
 */
export async function decryptSequence(
  encrypted: EncryptedSequence,
  masterKey: Buffer,
  memoryId: string,
): Promise<number[]> {
  const key = await deriveFragmentKey(masterKey, `chainlock-seq-${memoryId}`, encrypted.version);
  const plaintext = aesDecrypt(encrypted.ciphertext, key, encrypted.iv, encrypted.authTag);
  return JSON.parse(plaintext.toString('utf-8')) as number[];
}

/**
 * Validate a sequence using constant-time comparison.
 * Prevents timing attacks that could leak sequence information.
 */
export function validateSequence(
  provided: number[],
  expected: number[],
): boolean {
  if (provided.length !== expected.length) return false;

  const a = Buffer.from(JSON.stringify(provided));
  const b = Buffer.from(JSON.stringify(expected));

  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

/**
 * Rotate a sequence — generates a new random ordering.
 * Called after each successful recall to prevent replay.
 */
export async function rotateSequence(
  fragmentCount: number,
  masterKey: Buffer,
  memoryId: string,
  currentVersion: number,
): Promise<EncryptedSequence> {
  const newSequence = generateSequence(fragmentCount);
  return encryptSequence(newSequence, masterKey, memoryId, currentVersion + 1);
}

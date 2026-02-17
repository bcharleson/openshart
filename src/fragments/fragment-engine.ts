/**
 * @module fragment-engine
 * Orchestrates the fragment pipeline: plaintext → Shamir split → AES encrypt → encrypted fragments.
 */

import { randomUUID } from 'node:crypto';
import { split, reconstruct, type Share } from './shard.js';
import {
  aesEncrypt,
  aesDecrypt,
  deriveFragmentKey,
} from './encrypt.js';
import type { EncryptedFragment, MemoryId } from '../core/types.js';
import { fragmentId } from '../core/types.js';

/** Parameters for fragment creation */
export interface FragmentParams {
  /** Minimum shares to reconstruct */
  threshold: number;
  /** Total shares to generate */
  totalShares: number;
  /** Number of logical storage slots */
  slots: number;
}

/** Slot assignment character pool */
const SLOT_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';

/**
 * Fragment plaintext content into encrypted fragments.
 *
 * Pipeline: plaintext → Buffer → Shamir split → per-share AES-256-GCM encrypt → EncryptedFragment[]
 *
 * @param content - Plaintext content to fragment
 * @param memoryId - Unique memory identifier
 * @param masterKey - Master encryption key (32 bytes)
 * @param params - Fragment parameters (threshold, total, slots)
 * @returns Array of encrypted fragments ready for storage
 */
export async function fragmentContent(
  content: string,
  memoryId: MemoryId,
  masterKey: Buffer,
  params: FragmentParams,
): Promise<EncryptedFragment[]> {
  const plainBuffer = Buffer.from(content, 'utf-8');

  // Split via Shamir's Secret Sharing
  const shares = split(plainBuffer, params.threshold, params.totalShares);

  // Encrypt each share with a unique derived key
  const fragments: EncryptedFragment[] = [];
  for (let i = 0; i < shares.length; i++) {
    const share = shares[i]!;
    const key = await deriveFragmentKey(masterKey, memoryId, share.x);

    // Serialize share: [1 byte x-coordinate][share data]
    const shareBuffer = Buffer.alloc(1 + share.y.length);
    shareBuffer[0] = share.x;
    share.y.copy(shareBuffer, 1);

    const { ciphertext, iv, authTag } = aesEncrypt(shareBuffer, key);

    const slotIndex = i % params.slots;
    const slot = SLOT_CHARS[slotIndex % SLOT_CHARS.length]!;

    fragments.push({
      id: fragmentId(`frag_${randomUUID().replace(/-/g, '').slice(0, 16)}`),
      memoryId,
      index: i + 1,
      total: params.totalShares,
      ciphertext,
      iv,
      authTag,
      slot,
      createdAt: new Date().toISOString(),
    });
  }

  return fragments;
}

/**
 * Reconstruct content from encrypted fragments.
 *
 * Pipeline: EncryptedFragment[] → AES decrypt → Shamir reconstruct → plaintext
 *
 * @param fragments - At least K encrypted fragments
 * @param masterKey - Master encryption key (32 bytes)
 * @returns Reconstructed plaintext content
 * @throws If not enough fragments or decryption fails
 */
export async function reconstructContent(
  fragments: EncryptedFragment[],
  masterKey: Buffer,
): Promise<string> {
  if (fragments.length === 0) {
    throw new Error('No fragments provided for reconstruction');
  }

  // Decrypt each fragment to recover shares
  const shares: Share[] = [];
  for (const fragment of fragments) {
    const key = await deriveFragmentKey(masterKey, fragment.memoryId, fragment.index);

    const shareBuffer = aesDecrypt(
      fragment.ciphertext,
      key,
      fragment.iv,
      fragment.authTag,
    );

    shares.push({
      x: shareBuffer[0]!,
      y: shareBuffer.subarray(1),
    });
  }

  // Reconstruct via Shamir
  const plainBuffer = reconstruct(shares);
  return plainBuffer.toString('utf-8');
}

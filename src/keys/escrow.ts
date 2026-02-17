/**
 * @module keys/escrow
 * Key escrow for disaster recovery — split master key via Shamir's Secret Sharing.
 * M-of-N key holders can reconstruct the master key in emergency.
 * Separate from data fragmentation — this is for the KEY itself.
 */

import { randomBytes } from 'node:crypto';
import { split, reconstruct, type Share } from '../fragments/shard.js';
import { aesEncrypt, aesDecrypt } from '../fragments/encrypt.js';

/** A key escrow share held by a custodian */
export interface EscrowShare {
  /** Share identifier */
  id: string;
  /** Custodian identifier */
  custodianId: string;
  /** Encrypted share data (encrypted with custodian's key) */
  encryptedShare: Buffer;
  /** AES-GCM IV */
  iv: Buffer;
  /** AES-GCM auth tag */
  authTag: Buffer;
  /** Share index (x-coordinate) */
  shareIndex: number;
  /** Creation timestamp */
  createdAt: string;
}

/** Escrow configuration */
export interface EscrowConfig {
  /** Minimum shares needed to reconstruct (M) */
  threshold: number;
  /** Total shares to generate (N) */
  totalShares: number;
}

/**
 * Split a master key into escrow shares for M-of-N recovery.
 *
 * @param masterKey - The master key to escrow (32 bytes)
 * @param custodianKeys - Map of custodian ID → their encryption key (for encrypting their share)
 * @param config - M-of-N configuration
 * @returns Encrypted escrow shares, one per custodian
 */
export function createEscrow(
  masterKey: Buffer,
  custodianKeys: Map<string, Buffer>,
  config: EscrowConfig,
): EscrowShare[] {
  if (custodianKeys.size < config.totalShares) {
    throw new Error(
      `Need ${config.totalShares} custodians but only ${custodianKeys.size} provided`
    );
  }

  // Split master key via Shamir
  const shares = split(masterKey, config.threshold, config.totalShares);

  // Encrypt each share with the corresponding custodian's key
  const custodianIds = [...custodianKeys.keys()];
  const escrowShares: EscrowShare[] = [];

  for (let i = 0; i < shares.length; i++) {
    const share = shares[i]!;
    const custodianId = custodianIds[i]!;
    const custodianKey = custodianKeys.get(custodianId)!;

    // Serialize share
    const shareBuffer = Buffer.alloc(1 + share.y.length);
    shareBuffer[0] = share.x;
    share.y.copy(shareBuffer, 1);

    // Encrypt with custodian's key
    const { ciphertext, iv, authTag } = aesEncrypt(shareBuffer, custodianKey);

    escrowShares.push({
      id: `escrow_${randomBytes(8).toString('hex')}`,
      custodianId,
      encryptedShare: ciphertext,
      iv,
      authTag,
      shareIndex: share.x,
      createdAt: new Date().toISOString(),
    });
  }

  return escrowShares;
}

/**
 * Recover a master key from escrow shares.
 *
 * @param escrowShares - At least M escrow shares
 * @param custodianKeys - Map of custodian ID → their decryption key
 * @returns Reconstructed master key
 */
export function recoverFromEscrow(
  escrowShares: EscrowShare[],
  custodianKeys: Map<string, Buffer>,
): Buffer {
  const shares: Share[] = [];

  for (const escrow of escrowShares) {
    const custodianKey = custodianKeys.get(escrow.custodianId);
    if (!custodianKey) {
      throw new Error(`Missing key for custodian ${escrow.custodianId}`);
    }

    // Decrypt share
    const shareBuffer = aesDecrypt(
      escrow.encryptedShare,
      custodianKey,
      escrow.iv,
      escrow.authTag,
    );

    shares.push({
      x: shareBuffer[0]!,
      y: shareBuffer.subarray(1),
    });
  }

  // Reconstruct via Shamir
  return reconstruct(shares);
}

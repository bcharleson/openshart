/**
 * @module audit/chain
 * Hash chain verification — detect tampering in the audit log.
 */

import type { StorageBackend } from '../core/types.js';
import { computeEntryHash } from './logger.js';

/** Result of chain verification */
export interface ChainVerificationResult {
  valid: boolean;
  entriesChecked: number;
  /** Index of first invalid entry, or -1 if valid */
  firstInvalidIndex: number;
  /** Details about the failure */
  error?: string;
}

/**
 * Verify the integrity of the audit log hash chain.
 * Checks that each entry's hash matches its content and links to the previous entry.
 *
 * @param storage - Storage backend to read audit entries from
 * @returns Verification result
 */
export async function verifyAuditChain(
  storage: StorageBackend,
): Promise<ChainVerificationResult> {
  // Read all entries in chronological order
  const entries = await storage.readAuditLog({ limit: 1_000_000 });

  // Reverse to chronological order (readAuditLog returns newest first)
  entries.reverse();

  if (entries.length === 0) {
    return { valid: true, entriesChecked: 0, firstInvalidIndex: -1 };
  }

  let previousHash = '0'.repeat(64); // Genesis hash

  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i]!;

    // Check previousHash linkage
    if (entry.previousHash !== previousHash) {
      return {
        valid: false,
        entriesChecked: i + 1,
        firstInvalidIndex: i,
        error: `Entry ${entry.id} at index ${i}: previousHash mismatch. Expected ${previousHash}, got ${entry.previousHash}`,
      };
    }

    // Recompute hash and verify
    const { hash: _hash, ...rest } = entry;
    const expectedHash = computeEntryHash(rest);

    if (entry.hash !== expectedHash) {
      return {
        valid: false,
        entriesChecked: i + 1,
        firstInvalidIndex: i,
        error: `Entry ${entry.id} at index ${i}: hash mismatch. Content has been tampered with.`,
      };
    }

    previousHash = entry.hash;
  }

  return { valid: true, entriesChecked: entries.length, firstInvalidIndex: -1 };
}

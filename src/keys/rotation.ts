/**
 * @module keys/rotation
 * Automatic key rotation — re-encrypt fragments with new keys, securely destroy old keys.
 */

import { randomBytes } from 'node:crypto';
import type { StorageBackend, MemoryId } from '../core/types.js';
import { aesDecrypt, aesEncrypt, deriveFragmentKey } from '../fragments/encrypt.js';
import { secureDestroy } from './destruction.js';

/** Key rotation event */
export interface RotationEvent {
  memoryId: MemoryId;
  fragmentsRotated: number;
  oldKeyVersion: number;
  newKeyVersion: number;
  rotatedAt: string;
}

/** Key version metadata */
export interface KeyVersion {
  version: number;
  createdAt: string;
  retiredAt?: string;
  status: 'active' | 'retired' | 'destroyed';
}

/**
 * Key rotation manager.
 * Handles scheduled rotation and re-encryption of fragments.
 */
export class KeyRotationManager {
  private keyVersions: KeyVersion[] = [];
  private currentVersion = 1;

  constructor(
    private readonly storage: StorageBackend,
  ) {
    this.keyVersions.push({
      version: 1,
      createdAt: new Date().toISOString(),
      status: 'active',
    });
  }

  /**
   * Rotate the master key for a specific memory.
   * Re-encrypts all fragments with keys derived from the new master key.
   *
   * @param memoryId - Memory to rotate keys for
   * @param oldMasterKey - Current master key
   * @param newMasterKey - New master key
   * @returns Rotation event details
   */
  async rotateMemoryKey(
    memoryId: MemoryId,
    oldMasterKey: Buffer,
    newMasterKey: Buffer,
  ): Promise<RotationEvent> {
    const fragments = await this.storage.getFragments(memoryId);
    let rotated = 0;

    for (const fragment of fragments) {
      // Decrypt with old key
      const oldKey = await deriveFragmentKey(oldMasterKey, memoryId, fragment.index);
      const plaintext = aesDecrypt(fragment.ciphertext, oldKey, fragment.iv, fragment.authTag);

      // Re-encrypt with new key
      const newKey = await deriveFragmentKey(newMasterKey, memoryId, fragment.index);
      const { ciphertext, iv, authTag } = aesEncrypt(plaintext, newKey);

      // Update fragment
      fragment.ciphertext = ciphertext;
      fragment.iv = iv;
      fragment.authTag = authTag;
      await this.storage.putFragment(fragment);

      // Securely destroy derived keys
      secureDestroy(oldKey);
      secureDestroy(newKey);
      plaintext.fill(0);

      rotated++;
    }

    const newVersion = this.currentVersion + 1;

    // Retire old version
    const oldVersionEntry = this.keyVersions.find(v => v.version === this.currentVersion);
    if (oldVersionEntry) {
      oldVersionEntry.status = 'retired';
      oldVersionEntry.retiredAt = new Date().toISOString();
    }

    // Register new version
    this.keyVersions.push({
      version: newVersion,
      createdAt: new Date().toISOString(),
      status: 'active',
    });
    this.currentVersion = newVersion;

    return {
      memoryId,
      fragmentsRotated: rotated,
      oldKeyVersion: newVersion - 1,
      newKeyVersion: newVersion,
      rotatedAt: new Date().toISOString(),
    };
  }

  /**
   * Rotate keys for all memories in storage.
   */
  async rotateAll(
    oldMasterKey: Buffer,
    newMasterKey: Buffer,
  ): Promise<RotationEvent[]> {
    const allMeta = await this.storage.listMeta({});
    const events: RotationEvent[] = [];

    for (const meta of allMeta) {
      const event = await this.rotateMemoryKey(meta.id, oldMasterKey, newMasterKey);
      events.push(event);
    }

    return events;
  }

  /**
   * Get current key version.
   */
  getCurrentVersion(): number {
    return this.currentVersion;
  }

  /**
   * Get all key version history.
   */
  getVersionHistory(): KeyVersion[] {
    return [...this.keyVersions];
  }

  /**
   * Generate a new random master key.
   */
  static generateMasterKey(): Buffer {
    return randomBytes(32);
  }
}

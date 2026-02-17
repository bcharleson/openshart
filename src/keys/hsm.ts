/**
 * @module keys/hsm
 * HSM (Hardware Security Module) interface stub.
 * Defines the PKCS#11-style interface for HSM operations.
 * Software fallback when no HSM is available.
 */

import { randomBytes } from 'node:crypto';
import { aesEncrypt, aesDecrypt } from '../fragments/encrypt.js';

/** Opaque handle to a key stored in the HSM */
export interface KeyHandle {
  id: string;
  algorithm: string;
  label: string;
  extractable: boolean;
  createdAt: string;
}

/** HSM attestation result */
export interface AttestationResult {
  valid: boolean;
  keyId: string;
  algorithm: string;
  keySize: number;
  createdAt: string;
  hardwareBacked: boolean;
}

/**
 * HSM provider interface — PKCS#11 style operations.
 * Key material never leaves the HSM in a real implementation.
 */
export interface HSMProvider {
  /** Generate a new key inside the HSM */
  generateKey(algorithm: string, label: string): Promise<KeyHandle>;
  /** Import key material into the HSM */
  importKey(material: Buffer, label: string): Promise<KeyHandle>;
  /** Destroy a key in the HSM */
  destroyKey(handle: KeyHandle): Promise<void>;
  /** Encrypt data (key never leaves HSM) */
  encrypt(handle: KeyHandle, plaintext: Buffer, iv: Buffer): Promise<Buffer>;
  /** Decrypt data (key never leaves HSM) */
  decrypt(handle: KeyHandle, ciphertext: Buffer, iv: Buffer, authTag: Buffer): Promise<Buffer>;
  /** Sign data */
  sign(handle: KeyHandle, data: Buffer): Promise<Buffer>;
  /** Verify a signature */
  verify(handle: KeyHandle, data: Buffer, signature: Buffer): Promise<boolean>;
  /** Wrap a key for export/backup */
  wrapKey(wrappingHandle: KeyHandle, targetHandle: KeyHandle): Promise<Buffer>;
  /** Unwrap an imported key */
  unwrapKey(wrappingHandle: KeyHandle, wrappedKey: Buffer, label: string): Promise<KeyHandle>;
  /** Get attestation for a key */
  attest(handle: KeyHandle): Promise<AttestationResult>;
  /** Check if HSM is hardware-backed */
  isHardwareBacked(): boolean;
}

/**
 * Software fallback HSM provider.
 * Implements the HSM interface using Node.js crypto for development/testing.
 * NOT suitable for production government use — use a real HSM (AWS CloudHSM, Thales Luna, etc.)
 */
export class SoftwareHSMProvider implements HSMProvider {
  private keys = new Map<string, { handle: KeyHandle; material: Buffer }>();

  async generateKey(algorithm: string, label: string): Promise<KeyHandle> {
    const keySize = algorithm.includes('256') ? 32 : algorithm.includes('192') ? 24 : 16;
    const material = randomBytes(keySize);
    const handle: KeyHandle = {
      id: `swkey_${randomBytes(8).toString('hex')}`,
      algorithm,
      label,
      extractable: false,
      createdAt: new Date().toISOString(),
    };
    this.keys.set(handle.id, { handle, material });
    return handle;
  }

  async importKey(material: Buffer, label: string): Promise<KeyHandle> {
    const handle: KeyHandle = {
      id: `swkey_${randomBytes(8).toString('hex')}`,
      algorithm: `aes-${material.length * 8}-gcm`,
      label,
      extractable: false,
      createdAt: new Date().toISOString(),
    };
    // Copy material — don't hold reference to caller's buffer
    const copy = Buffer.alloc(material.length);
    material.copy(copy);
    this.keys.set(handle.id, { handle, material: copy });
    return handle;
  }

  async destroyKey(handle: KeyHandle): Promise<void> {
    const entry = this.keys.get(handle.id);
    if (entry) {
      entry.material.fill(0);
      this.keys.delete(handle.id);
    }
  }

  async encrypt(handle: KeyHandle, plaintext: Buffer, _iv: Buffer): Promise<Buffer> {
    const entry = this.keys.get(handle.id);
    if (!entry) throw new Error(`Key not found: ${handle.id}`);
    const result = aesEncrypt(plaintext, entry.material);
    // Return iv + authTag + ciphertext packed together
    return Buffer.concat([result.iv, result.authTag, result.ciphertext]);
  }

  async decrypt(handle: KeyHandle, ciphertext: Buffer, iv: Buffer, authTag: Buffer): Promise<Buffer> {
    const entry = this.keys.get(handle.id);
    if (!entry) throw new Error(`Key not found: ${handle.id}`);
    return aesDecrypt(ciphertext, entry.material, iv, authTag);
  }

  async sign(handle: KeyHandle, data: Buffer): Promise<Buffer> {
    const { createHmac } = await import('node:crypto');
    const entry = this.keys.get(handle.id);
    if (!entry) throw new Error(`Key not found: ${handle.id}`);
    return createHmac('sha256', entry.material).update(data).digest();
  }

  async verify(handle: KeyHandle, data: Buffer, signature: Buffer): Promise<boolean> {
    const expected = await this.sign(handle, data);
    if (expected.length !== signature.length) return false;
    let diff = 0;
    for (let i = 0; i < expected.length; i++) {
      diff |= expected[i]! ^ signature[i]!;
    }
    return diff === 0;
  }

  async wrapKey(wrappingHandle: KeyHandle, targetHandle: KeyHandle): Promise<Buffer> {
    const wrapper = this.keys.get(wrappingHandle.id);
    const target = this.keys.get(targetHandle.id);
    if (!wrapper || !target) throw new Error('Key not found');
    const result = aesEncrypt(target.material, wrapper.material);
    return Buffer.concat([result.iv, result.authTag, result.ciphertext]);
  }

  async unwrapKey(wrappingHandle: KeyHandle, wrappedKey: Buffer, label: string): Promise<KeyHandle> {
    const wrapper = this.keys.get(wrappingHandle.id);
    if (!wrapper) throw new Error(`Wrapping key not found: ${wrappingHandle.id}`);
    const iv = wrappedKey.subarray(0, 12);
    const authTag = wrappedKey.subarray(12, 28);
    const ciphertext = wrappedKey.subarray(28);
    const material = aesDecrypt(ciphertext, wrapper.material, iv, authTag);
    return this.importKey(material, label);
  }

  async attest(handle: KeyHandle): Promise<AttestationResult> {
    const entry = this.keys.get(handle.id);
    return {
      valid: !!entry,
      keyId: handle.id,
      algorithm: handle.algorithm,
      keySize: entry ? entry.material.length * 8 : 0,
      createdAt: handle.createdAt,
      hardwareBacked: false, // Software fallback
    };
  }

  isHardwareBacked(): boolean {
    return false;
  }
}

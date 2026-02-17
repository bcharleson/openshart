/**
 * @module encrypt
 * AES-256-GCM encryption/decryption for memory fragments.
 * Uses HKDF-SHA256 for per-fragment unique key derivation.
 */

import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  hkdf as nodeHkdf,
} from 'node:crypto';
import { promisify } from 'node:util';

const hkdfAsync = promisify(nodeHkdf);

/** HKDF info prefix for fragment key derivation */
const FRAGMENT_KEY_INFO_PREFIX = 'engram-fragment';

/** HKDF info prefix for search key derivation */
const SEARCH_KEY_INFO = 'engram-search';

/** HKDF info prefix for tag encryption */
const TAG_KEY_INFO = 'engram-tags';

/** Derive a unique key for a specific fragment using HKDF-SHA256 */
export async function deriveFragmentKey(
  masterKey: Buffer,
  memoryId: string,
  fragmentIndex: number,
): Promise<Buffer> {
  const info = `${FRAGMENT_KEY_INFO_PREFIX}-${fragmentIndex}`;
  const salt = Buffer.from(memoryId, 'utf-8');
  const derived = await hkdfAsync('sha256', masterKey, salt, info, 32);
  return Buffer.from(derived);
}

/** Derive the search key from master key */
export async function deriveSearchKey(masterKey: Buffer): Promise<Buffer> {
  const derived = await hkdfAsync('sha256', masterKey, Buffer.alloc(0), SEARCH_KEY_INFO, 32);
  return Buffer.from(derived);
}

/** Derive the tag encryption key from master key */
export async function deriveTagKey(masterKey: Buffer): Promise<Buffer> {
  const derived = await hkdfAsync('sha256', masterKey, Buffer.alloc(0), TAG_KEY_INFO, 32);
  return Buffer.from(derived);
}

/** Derive a department-scoped key from master key */
export async function deriveDepartmentKey(
  masterKey: Buffer,
  department: string,
): Promise<Buffer> {
  const derived = await hkdfAsync(
    'sha256',
    masterKey,
    Buffer.from(department, 'utf-8'),
    'engram-department',
    32,
  );
  return Buffer.from(derived);
}

/** Derive a hierarchy key for a specific role+department combination */
export async function deriveHierarchyKey(
  masterKey: Buffer,
  department: string,
  role: string,
): Promise<Buffer> {
  const derived = await hkdfAsync(
    'sha256',
    masterKey,
    Buffer.from(`${department}:${role}`, 'utf-8'),
    'engram-hierarchy',
    32,
  );
  return Buffer.from(derived);
}

/** Result of AES-256-GCM encryption */
export interface EncryptionResult {
  ciphertext: Buffer;
  iv: Buffer;
  authTag: Buffer;
}

/**
 * Encrypt data with AES-256-GCM.
 *
 * @param plaintext - Data to encrypt
 * @param key - 32-byte AES key
 * @returns Ciphertext, IV, and authentication tag
 */
export function aesEncrypt(plaintext: Buffer, key: Buffer): EncryptionResult {
  const iv = randomBytes(12); // 96-bit IV for GCM
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return { ciphertext, iv, authTag };
}

/**
 * Decrypt data with AES-256-GCM.
 *
 * @param ciphertext - Encrypted data
 * @param key - 32-byte AES key
 * @param iv - Initialization vector
 * @param authTag - Authentication tag
 * @returns Decrypted plaintext
 * @throws If authentication fails (tampered data)
 */
export function aesDecrypt(
  ciphertext: Buffer,
  key: Buffer,
  iv: Buffer,
  authTag: Buffer,
): Buffer {
  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

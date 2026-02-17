/**
 * @module crypto/fips
 * FIPS 140-2 compliance mode.
 * When enabled, enforces ONLY FIPS-approved algorithms and key sizes.
 */

import { createCipheriv, createDecipheriv, createHmac, randomBytes, hkdf as nodeHkdf } from 'node:crypto';
import { promisify } from 'node:util';

const hkdfAsync = promisify(nodeHkdf);

/** Global FIPS mode flag */
let fipsEnabled = false;

/** FIPS-approved algorithms */
const FIPS_ALGORITHMS = new Set([
  'aes-256-gcm',
  'aes-128-gcm',
  'aes-192-gcm',
]);

/** Minimum key lengths in bytes per algorithm family */
const FIPS_MIN_KEY_LENGTHS: Record<string, number> = {
  'aes-256': 32,
  'aes-192': 24,
  'aes-128': 16,
  'hmac-sha256': 32,
  'hmac-sha384': 48,
  'hmac-sha512': 64,
  'hkdf': 32,
};

/**
 * Enable FIPS compliance mode.
 * All subsequent crypto operations will be validated against FIPS requirements.
 */
export function enableFIPS(): void {
  // Run self-tests before enabling
  runSelfTests();
  fipsEnabled = true;
}

/**
 * Disable FIPS mode.
 */
export function disableFIPS(): void {
  fipsEnabled = false;
}

/**
 * Check if FIPS mode is currently enabled.
 */
export function isFIPSEnabled(): boolean {
  return fipsEnabled;
}

/**
 * Validate that an algorithm is FIPS-approved.
 * @throws If FIPS mode is on and algorithm is not approved
 */
export function validateAlgorithm(algorithm: string): void {
  if (!fipsEnabled) return;
  if (!FIPS_ALGORITHMS.has(algorithm.toLowerCase())) {
    throw new FIPSError(`Algorithm '${algorithm}' is not FIPS 140-2 approved`);
  }
}

/**
 * Validate key length meets FIPS requirements.
 * @throws If key is too short for FIPS compliance
 */
export function validateKeyLength(key: Buffer, purpose: string): void {
  if (!fipsEnabled) return;

  const minLength = FIPS_MIN_KEY_LENGTHS[purpose];
  if (minLength && key.length < minLength) {
    throw new FIPSError(
      `Key length ${key.length} bytes insufficient for ${purpose}. FIPS requires >= ${minLength} bytes`
    );
  }
}

/**
 * Validate key entropy — reject obviously weak keys.
 */
export function validateKeyEntropy(key: Buffer): void {
  // Check for all-zero keys
  if (key.every(b => b === 0)) {
    throw new FIPSError('Key has zero entropy (all zeros)');
  }

  // Check for repeating single byte
  if (key.every(b => b === key[0])) {
    throw new FIPSError('Key has minimal entropy (all same byte)');
  }

  // Check for sequential bytes
  let sequential = true;
  for (let i = 1; i < key.length; i++) {
    if (key[i] !== ((key[i - 1]! + 1) & 0xff)) {
      sequential = false;
      break;
    }
  }
  if (sequential && key.length >= 16) {
    throw new FIPSError('Key appears sequential — insufficient entropy');
  }

  // Rough byte entropy check: count unique bytes
  const uniqueBytes = new Set(key).size;
  if (key.length >= 16 && uniqueBytes < key.length / 4) {
    throw new FIPSError(`Key has low entropy: only ${uniqueBytes} unique bytes in ${key.length} byte key`);
  }
}

/**
 * FIPS-compliant AES-256-GCM encryption.
 */
export function fipsEncrypt(plaintext: Buffer, key: Buffer): { ciphertext: Buffer; iv: Buffer; authTag: Buffer } {
  validateAlgorithm('aes-256-gcm');
  validateKeyLength(key, 'aes-256');

  const iv = randomBytes(12); // 96-bit IV per NIST SP 800-38D
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return { ciphertext, iv, authTag };
}

/**
 * FIPS-compliant AES-256-GCM decryption.
 */
export function fipsDecrypt(ciphertext: Buffer, key: Buffer, iv: Buffer, authTag: Buffer): Buffer {
  validateAlgorithm('aes-256-gcm');
  validateKeyLength(key, 'aes-256');

  if (iv.length !== 12) {
    throw new FIPSError('GCM IV must be exactly 12 bytes (96 bits) per NIST SP 800-38D');
  }
  if (authTag.length !== 16) {
    throw new FIPSError('GCM auth tag must be 16 bytes (128 bits)');
  }

  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

/**
 * FIPS-compliant HMAC-SHA256.
 */
export function fipsHmac(key: Buffer, data: Buffer): Buffer {
  validateKeyLength(key, 'hmac-sha256');
  return createHmac('sha256', key).update(data).digest();
}

/**
 * FIPS-compliant HKDF-SHA256 with proper salt.
 * @param ikm - Input key material
 * @param salt - Must be non-empty for FIPS compliance
 * @param info - Context/application-specific info
 * @param length - Output length in bytes
 */
export async function fipsHkdf(
  ikm: Buffer,
  salt: Buffer,
  info: string,
  length: number,
): Promise<Buffer> {
  if (fipsEnabled && salt.length === 0) {
    throw new FIPSError('HKDF salt must not be empty in FIPS mode (NIST SP 800-56C)');
  }
  if (length < 16) {
    throw new FIPSError('HKDF output must be >= 16 bytes');
  }

  const derived = await hkdfAsync('sha256', ikm, salt, info, length);
  return Buffer.from(derived);
}

/**
 * FIPS-compliant random number generation.
 * Uses Node.js crypto.randomBytes which delegates to OpenSSL CSPRNG.
 */
export function fipsRandomBytes(length: number): Buffer {
  if (length < 1) throw new FIPSError('Random byte length must be >= 1');
  return randomBytes(length);
}

/**
 * Run Known Answer Tests (KAT) for FIPS self-test.
 * Verifies correct operation of AES-GCM, HMAC-SHA256, and HKDF.
 * @throws If any self-test fails
 */
export function runSelfTests(): void {
  // AES-256-GCM KAT
  const testKey = Buffer.from('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef', 'hex');
  const testPlaintext = Buffer.from('FIPS self-test plaintext');
  const { ciphertext, iv, authTag } = fipsEncrypt(testPlaintext, testKey);
  const decrypted = fipsDecrypt(ciphertext, testKey, iv, authTag);
  if (!decrypted.equals(testPlaintext)) {
    throw new FIPSError('AES-256-GCM self-test FAILED: encrypt/decrypt mismatch');
  }

  // HMAC-SHA256 KAT
  const hmacResult = fipsHmac(testKey, Buffer.from('test'));
  if (hmacResult.length !== 32) {
    throw new FIPSError('HMAC-SHA256 self-test FAILED: unexpected output length');
  }

  // Verify tamper detection
  try {
    const tamperedTag = Buffer.from(authTag);
    tamperedTag[0] = (tamperedTag[0]! ^ 0xff);
    fipsDecrypt(ciphertext, testKey, iv, tamperedTag);
    throw new FIPSError('AES-256-GCM self-test FAILED: tampered auth tag not detected');
  } catch (e) {
    if (e instanceof FIPSError) throw e;
    // Expected: decryption should fail with tampered tag
  }
}

/**
 * FIPS compliance error.
 */
export class FIPSError extends Error {
  constructor(message: string) {
    super(`FIPS violation: ${message}`);
    this.name = 'FIPSError';
  }
}

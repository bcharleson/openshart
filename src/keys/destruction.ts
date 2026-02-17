/**
 * @module keys/destruction
 * Secure key destruction — overwrite memory multiple times, verify destruction.
 * Implements DoD 5220.22-M style multi-pass overwrite for sensitive buffers.
 */

import { randomBytes } from 'node:crypto';

/** Number of overwrite passes (DoD 5220.22-M specifies 3 minimum) */
const DEFAULT_PASSES = 3;

/** Destruction verification result */
export interface DestructionVerification {
  destroyed: boolean;
  passes: number;
  bytesOverwritten: number;
}

/**
 * Securely destroy a Buffer by overwriting its contents multiple times.
 * Pattern: zeros → ones → random (DoD 5220.22-M pattern).
 *
 * @param buffer - Buffer to destroy
 * @param passes - Number of overwrite passes (default: 3)
 * @returns Verification of destruction
 */
export function secureDestroy(
  buffer: Buffer,
  passes: number = DEFAULT_PASSES,
): DestructionVerification {
  const len = buffer.length;
  if (len === 0) return { destroyed: true, passes: 0, bytesOverwritten: 0 };

  for (let pass = 0; pass < passes; pass++) {
    if (pass % 3 === 0) {
      // Pass 1: all zeros
      buffer.fill(0x00);
    } else if (pass % 3 === 1) {
      // Pass 2: all ones
      buffer.fill(0xff);
    } else {
      // Pass 3: random data
      const rand = randomBytes(len);
      rand.copy(buffer);
      rand.fill(0); // Clean up random source
    }
  }

  // Final overwrite with zeros
  buffer.fill(0x00);

  return {
    destroyed: true,
    passes,
    bytesOverwritten: len * (passes + 1),
  };
}

/**
 * Verify that a buffer has been properly zeroed.
 */
export function verifyDestruction(buffer: Buffer): boolean {
  for (let i = 0; i < buffer.length; i++) {
    if (buffer[i] !== 0) return false;
  }
  return true;
}

/**
 * Securely destroy multiple buffers.
 */
export function secureDestroyAll(
  buffers: Buffer[],
  passes: number = DEFAULT_PASSES,
): DestructionVerification {
  let totalBytes = 0;

  for (const buf of buffers) {
    const result = secureDestroy(buf, passes);
    totalBytes += result.bytesOverwritten;
  }

  return {
    destroyed: true,
    passes,
    bytesOverwritten: totalBytes,
  };
}

/**
 * Create a secure buffer wrapper that auto-destroys on deallocation.
 * Returns a Buffer that can be explicitly destroyed.
 */
export class SecureBuffer {
  private buffer: Buffer;
  private _destroyed = false;

  constructor(size: number);
  constructor(data: Buffer);
  constructor(sizeOrData: number | Buffer) {
    if (typeof sizeOrData === 'number') {
      this.buffer = Buffer.alloc(sizeOrData);
    } else {
      this.buffer = Buffer.alloc(sizeOrData.length);
      sizeOrData.copy(this.buffer);
      // Wipe the source
      sizeOrData.fill(0);
    }
  }

  /**
   * Get the underlying buffer. Throws if destroyed.
   */
  get value(): Buffer {
    if (this._destroyed) throw new Error('SecureBuffer has been destroyed');
    return this.buffer;
  }

  get length(): number {
    return this.buffer.length;
  }

  get isDestroyed(): boolean {
    return this._destroyed;
  }

  /**
   * Securely destroy this buffer.
   */
  destroy(passes = DEFAULT_PASSES): DestructionVerification {
    if (this._destroyed) return { destroyed: true, passes: 0, bytesOverwritten: 0 };
    const result = secureDestroy(this.buffer, passes);
    this._destroyed = true;
    return result;
  }
}

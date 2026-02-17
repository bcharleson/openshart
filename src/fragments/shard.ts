/**
 * @module shard
 * Shamir's Secret Sharing implementation over GF(2^8).
 *
 * Splits a secret into N shares where any K shares can reconstruct the original.
 * Uses arithmetic in GF(2^8) with the irreducible polynomial x^8 + x^4 + x^3 + x + 1
 * (0x11B, the AES polynomial).
 *
 * Security: K-1 shares reveal zero information about the secret (information-theoretic security).
 */

import { randomBytes } from 'node:crypto';

// ─── GF(2^8) Arithmetic ──────────────────────────────────────

/** Irreducible polynomial for GF(2^8): x^8 + x^4 + x^3 + x + 1 */
const PRIMITIVE_POLY = 0x11b;

/** Precomputed exp table for GF(2^8) */
const EXP_TABLE = new Uint8Array(512);
/** Precomputed log table for GF(2^8) */
const LOG_TABLE = new Uint8Array(256);

// Build lookup tables using generator 3
(function buildTables() {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP_TABLE[i] = x;
    LOG_TABLE[x] = i;
    x = x ^ gf256MulNoTable(x, 3);
  }
  // Wrap around for convenience
  for (let i = 255; i < 512; i++) {
    EXP_TABLE[i] = EXP_TABLE[i - 255]!;
  }
})();

/** Multiplication in GF(2^8) without lookup tables (used for table generation) */
function gf256MulNoTable(a: number, b: number): number {
  let result = 0;
  let aa = a;
  let bb = b;
  while (bb > 0) {
    if (bb & 1) result ^= aa;
    aa <<= 1;
    if (aa & 0x100) aa ^= PRIMITIVE_POLY;
    bb >>= 1;
  }
  return result;
}

/** Addition in GF(2^8) — XOR */
export function gf256Add(a: number, b: number): number {
  return a ^ b;
}

/** Subtraction in GF(2^8) — same as addition (XOR) */
export function gf256Sub(a: number, b: number): number {
  return a ^ b;
}

/** Multiplication in GF(2^8) using lookup tables */
export function gf256Mul(a: number, b: number): number {
  if (a === 0 || b === 0) return 0;
  return EXP_TABLE[LOG_TABLE[a]! + LOG_TABLE[b]!]!;
}

/** Division in GF(2^8) */
export function gf256Div(a: number, b: number): number {
  if (b === 0) throw new Error('Division by zero in GF(2^8)');
  if (a === 0) return 0;
  return EXP_TABLE[(LOG_TABLE[a]! - LOG_TABLE[b]! + 255) % 255]!;
}

/** Multiplicative inverse in GF(2^8) */
export function gf256Inv(a: number): number {
  if (a === 0) throw new Error('Zero has no inverse in GF(2^8)');
  return EXP_TABLE[255 - LOG_TABLE[a]!]!;
}

// ─── Polynomial Evaluation ───────────────────────────────────

/**
 * Evaluate a polynomial at point x in GF(2^8).
 * coefficients[0] is the constant term (the secret).
 */
function evaluatePolynomial(coefficients: Uint8Array, x: number): number {
  let result = 0;
  // Horner's method
  for (let i = coefficients.length - 1; i >= 0; i--) {
    result = gf256Add(gf256Mul(result, x), coefficients[i]!);
  }
  return result;
}

// ─── Shamir's Secret Sharing ─────────────────────────────────

/** A single share: (x, y) point on the polynomial */
export interface Share {
  /** Share index (1-based, used as x-coordinate) */
  x: number;
  /** Share data (y-values for each byte of the secret) */
  y: Buffer;
}

/**
 * Split a secret into N shares requiring K to reconstruct.
 *
 * @param secret - The secret data to split
 * @param k - Minimum shares needed to reconstruct (threshold)
 * @param n - Total shares to generate
 * @returns Array of N shares
 *
 * @throws If k < 2, n < k, or n > 255
 */
export function split(secret: Buffer, k: number, n: number): Share[] {
  if (k < 2) throw new Error(`Threshold k must be >= 2, got ${k}`);
  if (n < k) throw new Error(`Total shares n (${n}) must be >= threshold k (${k})`);
  if (n > 255) throw new Error(`Total shares n must be <= 255, got ${n}`);
  if (secret.length === 0) throw new Error('Secret must not be empty');

  const shares: Share[] = [];
  for (let i = 0; i < n; i++) {
    shares.push({ x: i + 1, y: Buffer.alloc(secret.length) });
  }

  // For each byte of the secret, generate a random polynomial and evaluate at each share's x
  for (let byteIdx = 0; byteIdx < secret.length; byteIdx++) {
    // Coefficients: [secret_byte, random, random, ..., random] (k coefficients total)
    const coefficients = new Uint8Array(k);
    coefficients[0] = secret[byteIdx]!;

    // Fill remaining coefficients with random values
    const randBytes = randomBytes(k - 1);
    for (let j = 1; j < k; j++) {
      coefficients[j] = randBytes[j - 1]!;
    }

    // Evaluate polynomial at each share point
    for (let i = 0; i < n; i++) {
      shares[i]!.y[byteIdx] = evaluatePolynomial(coefficients, i + 1);
    }
  }

  return shares;
}

/**
 * Reconstruct a secret from K or more shares using Lagrange interpolation.
 *
 * @param shares - At least K shares
 * @returns The reconstructed secret
 *
 * @throws If fewer than 2 shares provided or shares have inconsistent lengths
 */
export function reconstruct(shares: Share[]): Buffer {
  if (shares.length < 2) throw new Error('Need at least 2 shares to reconstruct');

  const secretLength = shares[0]!.y.length;
  for (const share of shares) {
    if (share.y.length !== secretLength) {
      throw new Error('All shares must have the same length');
    }
  }

  const secret = Buffer.alloc(secretLength);

  // Lagrange interpolation at x=0 for each byte position
  for (let byteIdx = 0; byteIdx < secretLength; byteIdx++) {
    let value = 0;

    for (let i = 0; i < shares.length; i++) {
      const xi = shares[i]!.x;
      const yi = shares[i]!.y[byteIdx]!;

      // Compute Lagrange basis polynomial evaluated at x=0
      let basis = 1;
      for (let j = 0; j < shares.length; j++) {
        if (i === j) continue;
        const xj = shares[j]!.x;
        // basis *= (0 - xj) / (xi - xj) in GF(2^8)
        // Since subtraction = XOR: (0 ^ xj) / (xi ^ xj) = xj / (xi ^ xj)
        basis = gf256Mul(basis, gf256Div(xj, gf256Sub(xi, xj)));
      }

      value = gf256Add(value, gf256Mul(yi, basis));
    }

    secret[byteIdx] = value;
  }

  return secret;
}

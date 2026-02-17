/**
 * @module chainlock/chain-token
 * Ephemeral chain tokens that link each decryption step.
 * Each step produces a token derived from fragment content + step metadata + previous token.
 * Tokens exist ONLY in memory — never persisted.
 */

import { createHmac, randomBytes } from 'node:crypto';

/** An ephemeral chain token — exists only in memory */
export interface ChainToken {
  /** The HMAC token value */
  value: Buffer;
  /** Step index this token was produced at */
  stepIndex: number;
  /** Timestamp when this token was created */
  createdAt: bigint; // hrtime
}

/**
 * Generate a session nonce for seeding the first chain token.
 * This is cryptographically random and unique per recall session.
 */
export function generateSessionNonce(): Buffer {
  return randomBytes(32);
}

/**
 * Produce a chain token from a decryption step.
 *
 * token = HMAC-SHA256(
 *   key: sessionNonce,
 *   data: fragmentContent || stepIndex || timestamp || previousToken
 * )
 *
 * @param fragmentContent - Decrypted fragment content from this step
 * @param stepIndex - Current step number (0-based)
 * @param timestamp - Current high-resolution timestamp
 * @param previousToken - Token from previous step (or session nonce for first step)
 * @param sessionNonce - Session nonce for HMAC key
 * @returns New chain token
 */
export function produceChainToken(
  fragmentContent: Buffer,
  stepIndex: number,
  timestamp: bigint,
  previousToken: Buffer,
  sessionNonce: Buffer,
): ChainToken {
  const hmac = createHmac('sha256', sessionNonce);

  // Feed all inputs into the HMAC
  hmac.update(fragmentContent);
  hmac.update(Buffer.from(stepIndex.toString()));
  hmac.update(Buffer.from(timestamp.toString()));
  hmac.update(previousToken);

  const value = hmac.digest();

  return {
    value,
    stepIndex,
    createdAt: timestamp,
  };
}

/**
 * Verify that a chain token is valid for the current step.
 * Recomputes the expected token and compares.
 *
 * @param token - Token to verify
 * @param fragmentContent - Decrypted fragment content
 * @param stepIndex - Expected step index
 * @param timestamp - Timestamp used when token was created
 * @param previousToken - Previous token in the chain
 * @param sessionNonce - Session nonce
 * @returns Whether the token is valid
 */
export function verifyChainToken(
  token: ChainToken,
  fragmentContent: Buffer,
  stepIndex: number,
  timestamp: bigint,
  previousToken: Buffer,
  sessionNonce: Buffer,
): boolean {
  const expected = produceChainToken(
    fragmentContent,
    stepIndex,
    timestamp,
    previousToken,
    sessionNonce,
  );

  if (token.value.length !== expected.value.length) return false;

  // Constant-time comparison
  let diff = 0;
  for (let i = 0; i < token.value.length; i++) {
    diff |= token.value[i]! ^ expected.value[i]!;
  }
  return diff === 0;
}

/**
 * Securely wipe a chain token from memory.
 * Overwrites the buffer contents with zeros.
 */
export function wipeChainToken(token: ChainToken): void {
  token.value.fill(0);
}

/**
 * Wipe a session nonce from memory.
 */
export function wipeSessionNonce(nonce: Buffer): void {
  nonce.fill(0);
}

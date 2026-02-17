/**
 * @module chainlock
 * ChainLock — Temporal Sequence Lock for fragment decryption.
 *
 * A novel security primitive: fragments must be decrypted in a specific sequence,
 * within time windows, with chain tokens passed between steps.
 */

// Protocol
export { ChainLockProtocol, ChainLockError } from './protocol.js';
export type { ChainLockConfig, ChainLockRecallResult } from './protocol.js';

// Sequence
export {
  generateSequence,
  encryptSequence,
  decryptSequence,
  validateSequence,
  rotateSequence,
} from './sequence.js';
export type { EncryptedSequence } from './sequence.js';

// Temporal
export {
  createTemporalConfig,
  signTimestamp,
  verifyTimestamp,
  checkStepWindow,
  checkTotalCeiling,
} from './temporal.js';
export type { TemporalConfig, SignedTimestamp, WindowCheckResult } from './temporal.js';

// Chain Tokens
export {
  generateSessionNonce,
  produceChainToken,
  verifyChainToken,
  wipeChainToken,
  wipeSessionNonce,
} from './chain-token.js';
export type { ChainToken } from './chain-token.js';

// Breach Detection
export { BreachDetector, BreachEventType } from './breach-detection.js';
export type { BreachEvent, BreachDetectionConfig } from './breach-detection.js';

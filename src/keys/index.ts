/**
 * @module keys
 * Key management — rotation, escrow, destruction, HSM integration.
 */

export { KeyRotationManager } from './rotation.js';
export type { RotationEvent, KeyVersion } from './rotation.js';

export { createEscrow, recoverFromEscrow } from './escrow.js';
export type { EscrowShare, EscrowConfig } from './escrow.js';

export { secureDestroy, verifyDestruction, secureDestroyAll, SecureBuffer } from './destruction.js';
export type { DestructionVerification } from './destruction.js';

export { SoftwareHSMProvider } from './hsm.js';
export type { HSMProvider, KeyHandle, AttestationResult } from './hsm.js';

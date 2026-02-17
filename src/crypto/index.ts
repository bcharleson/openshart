/**
 * @module crypto
 * Cryptographic module with FIPS compliance support.
 */

export {
  enableFIPS,
  disableFIPS,
  isFIPSEnabled,
  validateAlgorithm,
  validateKeyLength,
  validateKeyEntropy,
  fipsEncrypt,
  fipsDecrypt,
  fipsHmac,
  fipsHkdf,
  fipsRandomBytes,
  runSelfTests,
  FIPSError,
} from './fips.js';

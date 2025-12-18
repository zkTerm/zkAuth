export {
  encryptWithMasterKey,
  decryptWithMasterKey,
  hashWithSHA256,
  deriveEncryptionKey,
  generateRandomIV,
  verifyBackupCode,
} from './crypto';

export {
  fetch2FAPointerFromSolana,
  searchMemosByLookupKey,
  fetchFromIPFS,
  parseTwoFAState,
  get2FAStateFromChain,
  derive2FALookupKeyClient,
} from './storage';

export type {
  HeliusConfig,
  StorageConfig,
} from './storage';

export {
  verifyTOTP,
  generateTOTPSecret,
  generateTOTPUri,
  generateQRCode,
  generateCurrentCode,
  getTimeRemaining,
  getTOTPConfig,
} from './totp';

export type {
  TwoFAState,
  TwoFAPointer,
  EncryptedTwoFAData,
  DecryptedTwoFAState,
  SolanaMemoTransaction,
  HeliusSearchResult,
  IPFSGatewayConfig,
  TwoFAVerificationResult,
} from './types';

export { DEFAULT_IPFS_GATEWAYS } from './types';

export { ZkAuth, createZkAuth } from './zkAuthClient';

export {
  generateMasterKey,
  masterKeyFromHex,
  hashMasterKey,
  deriveEncryptionKey,
  encryptWithPK,
  decryptWithPK,
  encryptData,
  decryptData,
  generateUserId,
  deriveWrappingKey,
  encryptWithWrappingKey,
  decryptWithWrappingKey
} from './masterkey';

export {
  splitMasterKey,
  combineShares,
  encryptShare,
  decryptShare,
  encryptShareWithGoogle,
  decryptShareWithGoogle,
  getChainForShareIndex
} from './shares';

export {
  ZcashShareStorage,
  createZcashStorage,
  StarknetShareStorage,
  createStarknetStorage,
  SolanaShareStorage,
  createSolanaStorage
} from './chains';

export {
  initializeLookupSalt,
  deriveLookupKeys,
  deriveShareLookupKeys,
  deriveEmailLookupKey,
  deriveUserId,
  deriveSolanaMemoPrefix,
  derive2FALookupKey,
  type LookupKeys,
  type ShareLookupKey
} from './lookup';

export {
  computeCommitment,
  generateProof,
  verifyProof,
  verifyProofForCommitment,
  type ZkAuthProof,
  type ZkAuthProofInput
} from './proof';

export type {
  ZkAuthConfig,
  ZcashConfig,
  StarknetConfig,
  SolanaConfig,
  MasterKey,
  EncryptedShare,
  ShareData,
  SplitResult,
  RegisterResult,
  LoginResult,
  ChainShareStorage,
  EncryptionResult,
  DecryptionResult,
  ChainType,
  ZkAuthSession
} from './types';

// Client-side React hooks and utilities
export {
  deriveLookupKey,
  get2FALocalStorageKey,
  parse2FAData,
  isValid2FASession,
  storeEmailOTP2FAMarker,
  clear2FAData,
  useZkAuthSession,
  useSessionValidation,
  useTwoFactorFlow,
  use2FAStatus,
  useVerifyTOTP,
  useVerifyEmailOTP,
  useSetup2FA,
} from './client/index';

export type {
  TwoFALocalData,
  GoogleUser,
  UseZkAuthSessionReturn,
  UseSessionValidationProps,
  UseSessionValidationReturn,
  UseTwoFactorFlowProps,
  UseTwoFactorFlowReturn,
  Use2FAStatusProps,
  Use2FAStatusReturn,
  UseVerifyTOTPProps,
  UseVerifyTOTPReturn,
  UseVerifyEmailOTPProps,
  UseVerifyEmailOTPReturn,
  UseSetup2FAProps,
  UseSetup2FAReturn,
  Setup2FAResult,
} from './client/index';

// Decentralized session token system
export {
  createSessionToken,
  parseSessionToken,
  verifySessionToken,
  getTokenPublicKey,
  isTokenExpired,
  getTokenTTL,
  storeSessionToken,
  getStoredSessionToken,
  clearSessionToken,
  SESSION_TOKEN_KEY,
} from './sessionToken';

export type {
  SessionTokenPayload,
  SessionToken,
} from './sessionToken';

// Client-side 2FA verification module (browser-native, no server calls)
export {
  // Crypto functions (Web Crypto API)
  encryptWithMasterKey,
  decryptWithMasterKey,
  hashWithSHA256,
  deriveEncryptionKey as derive2FAEncryptionKey,
  generateRandomIV,
  verifyBackupCode,
  // Storage functions (Solana/IPFS)
  fetch2FAPointerFromSolana,
  searchMemosByLookupKey,
  fetchFromIPFS,
  parseTwoFAState,
  get2FAStateFromChain,
  derive2FALookupKeyClient,
  // TOTP functions
  verifyTOTP,
  generateTOTPSecret,
  generateTOTPUri,
  generateQRCode,
  generateCurrentCode,
  getTimeRemaining,
  getTOTPConfig,
  // Constants
  DEFAULT_IPFS_GATEWAYS,
} from './zk2fa';

export type {
  // 2FA Types
  TwoFAState,
  TwoFAPointer,
  EncryptedTwoFAData,
  DecryptedTwoFAState,
  SolanaMemoTransaction,
  HeliusSearchResult,
  IPFSGatewayConfig,
  TwoFAVerificationResult,
  HeliusConfig,
  StorageConfig,
} from './zk2fa';

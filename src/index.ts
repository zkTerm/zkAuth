export { ZkAuth, createZkAuth } from './client';

export {
  generateMasterKey,
  masterKeyFromHex,
  hashMasterKey,
  deriveEncryptionKey,
  encryptWithPK,
  decryptWithPK,
  encryptData,
  decryptData,
  generateUserId
} from './masterkey';

export {
  splitMasterKey,
  combineShares,
  encryptShare,
  decryptShare,
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

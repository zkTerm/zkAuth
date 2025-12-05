export interface ZkAuthConfig {
  chains: {
    zcash?: ZcashConfig;
    starknet?: StarknetConfig;
    solana?: SolanaConfig;
  };
  threshold?: number;
  totalShares?: number;
}

export interface ZcashConfig {
  rpcUrl: string;
  network?: 'mainnet' | 'testnet';
}

export interface StarknetConfig {
  rpcUrl: string;
  contractAddress?: string;
  network?: 'mainnet' | 'sepolia';
}

export interface SolanaConfig {
  rpcUrl: string;
  programId?: string;
  network?: 'mainnet-beta' | 'devnet' | 'testnet';
}

export interface MasterKey {
  key: string;
  keyBytes: Uint8Array;
  createdAt: number;
}

export interface EncryptedShare {
  shareIndex: number;
  encryptedData: string;
  iv: string;
  tag: string;
  chain: 'zcash' | 'starknet' | 'solana';
  txHash?: string;
  storageAddress?: string;
}

export interface ShareData {
  x: string;
  y: string;
}

export interface SplitResult {
  shares: ShareData[];
  threshold: number;
  totalShares: number;
}

export interface RegisterResult {
  success: boolean;
  userId: string;
  shares: EncryptedShare[];
  masterKeyHash: string;
}

export interface LoginResult {
  success: boolean;
  userId: string;
  masterKey: MasterKey;
  sharesUsed: number;
}

export interface ChainShareStorage {
  store(userId: string, share: EncryptedShare): Promise<string>;
  fetch(userId: string): Promise<EncryptedShare | null>;
  exists(userId: string): Promise<boolean>;
}

export interface EncryptionResult {
  ciphertext: string;
  iv: string;
  tag: string;
}

export interface DecryptionResult {
  plaintext: string;
}

export type ChainType = 'zcash' | 'starknet' | 'solana';

export interface ZkAuthSession {
  userId: string;
  masterKey: MasterKey;
  expiresAt: number;
  encrypt(data: string): Promise<EncryptionResult>;
  decrypt(encrypted: EncryptionResult): Promise<string>;
}

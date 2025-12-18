import type {
  ZkAuthConfig,
  MasterKey,
  EncryptedShare,
  ShareData,
  RegisterResult,
  LoginResult,
  ZkAuthSession,
  EncryptionResult,
  ChainType
} from './types';
import {
  generateMasterKey,
  masterKeyFromHex,
  hashMasterKey,
  generateUserId,
  encryptData,
  decryptData
} from './masterkey';
import {
  splitMasterKey,
  combineShares,
  encryptShare,
  decryptShare,
  getChainForShareIndex
} from './shares';
import { ZcashShareStorage, createZcashStorage } from './chains/zcash';
import { StarknetShareStorage, createStarknetStorage } from './chains/starknet';
import { SolanaShareStorage, createSolanaStorage } from './chains/solana';

export class ZkAuth {
  private config: ZkAuthConfig;
  private zcashStorage?: ZcashShareStorage;
  private starknetStorage?: StarknetShareStorage;
  private solanaStorage?: SolanaShareStorage;
  private threshold: number;
  private totalShares: number;
  
  constructor(config: ZkAuthConfig) {
    this.config = config;
    this.threshold = config.threshold || 2;
    this.totalShares = config.totalShares || 3;
    
    if (config.chains.zcash) {
      this.zcashStorage = createZcashStorage(config.chains.zcash);
    }
    if (config.chains.starknet) {
      this.starknetStorage = createStarknetStorage(config.chains.starknet);
    }
    if (config.chains.solana) {
      this.solanaStorage = createSolanaStorage(config.chains.solana);
    }
    
    const enabledChains = this.getEnabledChains();
    if (enabledChains.length < this.threshold) {
      throw new Error(`At least ${this.threshold} chains must be configured for ${this.threshold}-of-${this.totalShares} threshold`);
    }
  }
  
  private getEnabledChains(): ChainType[] {
    const chains: ChainType[] = [];
    if (this.zcashStorage) chains.push('zcash');
    if (this.starknetStorage) chains.push('starknet');
    if (this.solanaStorage) chains.push('solana');
    return chains;
  }
  
  private getStorageForChain(chain: ChainType) {
    switch (chain) {
      case 'zcash': return this.zcashStorage;
      case 'starknet': return this.starknetStorage;
      case 'solana': return this.solanaStorage;
      default: return undefined;
    }
  }
  
  async register(pk: string): Promise<RegisterResult> {
    console.log('[ZkAuth] Starting registration...');
    
    const userId = generateUserId(pk);
    console.log(`[ZkAuth] User ID: ${userId}`);
    
    const isRegistered = await this.isRegistered(userId);
    if (isRegistered) {
      throw new Error('User already registered. Use login() instead.');
    }
    
    const masterKey = generateMasterKey();
    console.log('[ZkAuth] Master key generated');
    
    const splitResult = splitMasterKey(masterKey, this.threshold, this.totalShares);
    console.log(`[ZkAuth] Master key split into ${splitResult.totalShares} shares (threshold: ${splitResult.threshold})`);
    
    const encryptedShares: EncryptedShare[] = [];
    const enabledChains = this.getEnabledChains();
    
    for (let i = 0; i < splitResult.shares.length && i < enabledChains.length; i++) {
      const share = splitResult.shares[i];
      const chain = enabledChains[i];
      const shareIndex = i + 1;
      
      const encryptedShare = encryptShare(share, shareIndex, chain, pk);
      
      const storage = this.getStorageForChain(chain);
      if (storage) {
        const txHash = await storage.store(userId, encryptedShare);
        encryptedShare.txHash = txHash;
      }
      
      encryptedShares.push(encryptedShare);
      console.log(`[ZkAuth] Share ${shareIndex} stored on ${chain}`);
    }
    
    const masterKeyHash = hashMasterKey(masterKey);
    
    console.log('[ZkAuth] Registration complete!');
    
    return {
      success: true,
      userId,
      shares: encryptedShares,
      masterKeyHash
    };
  }
  
  async login(pk: string): Promise<LoginResult> {
    console.log('[ZkAuth] Starting login...');
    
    const userId = generateUserId(pk);
    console.log(`[ZkAuth] User ID: ${userId}`);
    
    const isRegistered = await this.isRegistered(userId);
    if (!isRegistered) {
      throw new Error('User not registered. Use register() first.');
    }
    
    const enabledChains = this.getEnabledChains();
    const fetchedShares: ShareData[] = [];
    let sharesUsed = 0;
    
    for (const chain of enabledChains) {
      if (fetchedShares.length >= this.threshold) break;
      
      const storage = this.getStorageForChain(chain);
      if (!storage) continue;
      
      try {
        const encryptedShare = await storage.fetch(userId);
        if (encryptedShare) {
          const share = decryptShare(encryptedShare, pk);
          fetchedShares.push(share);
          sharesUsed++;
          console.log(`[ZkAuth] Share fetched and decrypted from ${chain}`);
        }
      } catch (error) {
        console.log(`[ZkAuth] Failed to fetch share from ${chain}: ${error}`);
      }
    }
    
    if (fetchedShares.length < this.threshold) {
      throw new Error(`Not enough shares to reconstruct. Got ${fetchedShares.length}, need ${this.threshold}`);
    }
    
    const masterKeyHex = combineShares(fetchedShares);
    const masterKey = masterKeyFromHex(masterKeyHex);
    
    console.log('[ZkAuth] Master key reconstructed successfully!');
    
    return {
      success: true,
      userId,
      masterKey,
      sharesUsed
    };
  }
  
  async isRegistered(userId: string): Promise<boolean> {
    const enabledChains = this.getEnabledChains();
    let foundCount = 0;
    
    for (const chain of enabledChains) {
      const storage = this.getStorageForChain(chain);
      if (storage && await storage.exists(userId)) {
        foundCount++;
      }
    }
    
    return foundCount >= this.threshold;
  }
  
  createSession(loginResult: LoginResult, expiresInMs: number = 24 * 60 * 60 * 1000): ZkAuthSession {
    const expiresAt = Date.now() + expiresInMs;
    const { userId, masterKey } = loginResult;
    
    return {
      userId,
      masterKey,
      expiresAt,
      encrypt: async (data: string): Promise<EncryptionResult> => {
        if (Date.now() > expiresAt) {
          throw new Error('Session expired');
        }
        return encryptData(data, masterKey);
      },
      decrypt: async (encrypted: EncryptionResult): Promise<string> => {
        if (Date.now() > expiresAt) {
          throw new Error('Session expired');
        }
        return decryptData(encrypted, masterKey);
      }
    };
  }
  
  encrypt(data: string, masterKey: MasterKey): EncryptionResult {
    return encryptData(data, masterKey);
  }
  
  decrypt(encrypted: EncryptionResult, masterKey: MasterKey): string {
    return decryptData(encrypted, masterKey);
  }
  
  getUserId(pk: string): string {
    return generateUserId(pk);
  }
  
  getConfig(): ZkAuthConfig {
    return this.config;
  }
  
  getThreshold(): number {
    return this.threshold;
  }
  
  getTotalShares(): number {
    return this.totalShares;
  }
}

export function createZkAuth(config: ZkAuthConfig): ZkAuth {
  return new ZkAuth(config);
}

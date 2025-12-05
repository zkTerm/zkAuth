import type { EncryptedShare, ZcashConfig, ChainShareStorage } from '../types';

export class ZcashShareStorage implements ChainShareStorage {
  private config: ZcashConfig;
  private memoryStore: Map<string, EncryptedShare> = new Map();
  
  constructor(config: ZcashConfig) {
    this.config = config;
  }
  
  async store(userId: string, share: EncryptedShare): Promise<string> {
    const storageKey = this.getStorageKey(userId);
    
    this.memoryStore.set(storageKey, share);
    
    const mockTxHash = `zcash_tx_${Date.now()}_${Math.random().toString(36).substring(7)}`;
    
    console.log(`[Zcash] Share stored for user ${userId}`);
    console.log(`[Zcash] Mock TX: ${mockTxHash}`);
    
    return mockTxHash;
  }
  
  async fetch(userId: string): Promise<EncryptedShare | null> {
    const storageKey = this.getStorageKey(userId);
    
    const share = this.memoryStore.get(storageKey);
    
    if (share) {
      console.log(`[Zcash] Share fetched for user ${userId}`);
      return share;
    }
    
    console.log(`[Zcash] No share found for user ${userId}`);
    return null;
  }
  
  async exists(userId: string): Promise<boolean> {
    const storageKey = this.getStorageKey(userId);
    return this.memoryStore.has(storageKey);
  }
  
  private getStorageKey(userId: string): string {
    return `zcash:${userId}:share`;
  }
  
  async storeOnChain(userId: string, share: EncryptedShare): Promise<string> {
    const shareData = JSON.stringify({
      shareIndex: share.shareIndex,
      encryptedData: share.encryptedData,
      iv: share.iv,
      tag: share.tag,
      chain: share.chain
    });
    
    console.log(`[Zcash] Storing share on-chain for user ${userId}`);
    console.log(`[Zcash] Share data size: ${shareData.length} bytes`);
    
    const txHash = await this.store(userId, share);
    
    return txHash;
  }
  
  async fetchFromChain(userId: string): Promise<EncryptedShare | null> {
    console.log(`[Zcash] Fetching share from chain for user ${userId}`);
    
    return this.fetch(userId);
  }
  
  getConfig(): ZcashConfig {
    return this.config;
  }
}

export function createZcashStorage(config: ZcashConfig): ZcashShareStorage {
  return new ZcashShareStorage(config);
}

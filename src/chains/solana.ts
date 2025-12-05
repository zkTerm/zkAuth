import type { EncryptedShare, SolanaConfig, ChainShareStorage } from '../types';

export class SolanaShareStorage implements ChainShareStorage {
  private config: SolanaConfig;
  private memoryStore: Map<string, EncryptedShare> = new Map();
  
  constructor(config: SolanaConfig) {
    this.config = config;
  }
  
  async store(userId: string, share: EncryptedShare): Promise<string> {
    const storageKey = this.getStorageKey(userId);
    
    this.memoryStore.set(storageKey, share);
    
    const chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
    let mockTxHash = '';
    for (let i = 0; i < 88; i++) {
      mockTxHash += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    
    console.log(`[Solana] Share stored for user ${userId}`);
    console.log(`[Solana] Mock TX: ${mockTxHash}`);
    
    return mockTxHash;
  }
  
  async fetch(userId: string): Promise<EncryptedShare | null> {
    const storageKey = this.getStorageKey(userId);
    
    const share = this.memoryStore.get(storageKey);
    
    if (share) {
      console.log(`[Solana] Share fetched for user ${userId}`);
      return share;
    }
    
    console.log(`[Solana] No share found for user ${userId}`);
    return null;
  }
  
  async exists(userId: string): Promise<boolean> {
    const storageKey = this.getStorageKey(userId);
    return this.memoryStore.has(storageKey);
  }
  
  private getStorageKey(userId: string): string {
    return `solana:${userId}:share`;
  }
  
  async storeOnChain(userId: string, share: EncryptedShare): Promise<string> {
    const shareData = JSON.stringify({
      shareIndex: share.shareIndex,
      encryptedData: share.encryptedData,
      iv: share.iv,
      tag: share.tag,
      chain: share.chain
    });
    
    console.log(`[Solana] Storing share on-chain for user ${userId}`);
    console.log(`[Solana] Share data size: ${shareData.length} bytes`);
    
    const txHash = await this.store(userId, share);
    
    return txHash;
  }
  
  async fetchFromChain(userId: string): Promise<EncryptedShare | null> {
    console.log(`[Solana] Fetching share from chain for user ${userId}`);
    
    return this.fetch(userId);
  }
  
  getConfig(): SolanaConfig {
    return this.config;
  }
  
  getProgramId(): string | undefined {
    return this.config.programId;
  }
}

export function createSolanaStorage(config: SolanaConfig): SolanaShareStorage {
  return new SolanaShareStorage(config);
}

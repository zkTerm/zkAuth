import type { EncryptedShare, StarknetConfig, ChainShareStorage } from '../types';

export class StarknetShareStorage implements ChainShareStorage {
  private config: StarknetConfig;
  private memoryStore: Map<string, EncryptedShare> = new Map();
  
  constructor(config: StarknetConfig) {
    this.config = config;
  }
  
  async store(userId: string, share: EncryptedShare): Promise<string> {
    const storageKey = this.getStorageKey(userId);
    
    this.memoryStore.set(storageKey, share);
    
    const mockTxHash = `0x${Date.now().toString(16)}${Math.random().toString(16).substring(2, 10)}`;
    
    console.log(`[Starknet] Share stored for user ${userId}`);
    console.log(`[Starknet] Mock TX: ${mockTxHash}`);
    
    return mockTxHash;
  }
  
  async fetch(userId: string): Promise<EncryptedShare | null> {
    const storageKey = this.getStorageKey(userId);
    
    const share = this.memoryStore.get(storageKey);
    
    if (share) {
      console.log(`[Starknet] Share fetched for user ${userId}`);
      return share;
    }
    
    console.log(`[Starknet] No share found for user ${userId}`);
    return null;
  }
  
  async exists(userId: string): Promise<boolean> {
    const storageKey = this.getStorageKey(userId);
    return this.memoryStore.has(storageKey);
  }
  
  private getStorageKey(userId: string): string {
    return `starknet:${userId}:share`;
  }
  
  async storeOnChain(userId: string, share: EncryptedShare): Promise<string> {
    const shareData = JSON.stringify({
      shareIndex: share.shareIndex,
      encryptedData: share.encryptedData,
      iv: share.iv,
      tag: share.tag,
      chain: share.chain
    });
    
    console.log(`[Starknet] Storing share on-chain for user ${userId}`);
    console.log(`[Starknet] Share data size: ${shareData.length} bytes`);
    
    const txHash = await this.store(userId, share);
    
    return txHash;
  }
  
  async fetchFromChain(userId: string): Promise<EncryptedShare | null> {
    console.log(`[Starknet] Fetching share from chain for user ${userId}`);
    
    return this.fetch(userId);
  }
  
  getConfig(): StarknetConfig {
    return this.config;
  }
  
  getContractAddress(): string | undefined {
    return this.config.contractAddress;
  }
}

export function createStarknetStorage(config: StarknetConfig): StarknetShareStorage {
  return new StarknetShareStorage(config);
}

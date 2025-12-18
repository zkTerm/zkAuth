import type {
  TwoFAState,
  TwoFAPointer,
  SolanaMemoTransaction,
} from './types';

const MEMO_PROGRAM_ID = 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr';

export interface HeliusConfig {
  apiKey: string;
  cluster?: 'mainnet-beta' | 'devnet';
}

export interface StorageConfig {
  helius: HeliusConfig;
  ipfsGateways?: string[];
  timeout?: number;
}

function getHeliusUrl(config: HeliusConfig): string {
  const cluster = config.cluster || 'mainnet-beta';
  return `https://${cluster}.helius-rpc.com/?api-key=${config.apiKey}`;
}

export async function fetch2FAPointerFromSolana(
  lookupKey: string,
  walletAddress: string,
  config: StorageConfig
): Promise<TwoFAPointer | null> {
  const heliusUrl = getHeliusUrl(config.helius);
  
  try {
    const response = await fetch(heliusUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'getSignaturesForAddress',
        params: [
          walletAddress,
          { limit: 100 }
        ],
      }),
      signal: AbortSignal.timeout(config.timeout || 10000),
    });

    const data = await response.json() as { error?: unknown; result?: Array<{ signature: string }> };
    
    if (data.error) {
      console.error('[zk2fa] Helius RPC error:', data.error);
      return null;
    }

    const signatures = data.result || [];
    
    for (const sig of signatures) {
      const pointer = await fetchMemoFromTransaction(
        sig.signature,
        lookupKey,
        config
      );
      if (pointer) {
        return pointer;
      }
    }

    return null;
  } catch (error) {
    console.error('[zk2fa] Error fetching 2FA pointer from Solana:', error);
    return null;
  }
}

async function fetchMemoFromTransaction(
  signature: string,
  lookupKey: string,
  config: StorageConfig
): Promise<TwoFAPointer | null> {
  const heliusUrl = getHeliusUrl(config.helius);

  try {
    const response = await fetch(heliusUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'getTransaction',
        params: [
          signature,
          { encoding: 'jsonParsed', maxSupportedTransactionVersion: 0 }
        ],
      }),
      signal: AbortSignal.timeout(config.timeout || 10000),
    });

    const data = await response.json() as { error?: unknown; result?: { blockTime?: number; transaction?: { message?: { instructions?: Array<{ programId: string; parsed?: unknown }> } } } };
    
    if (data.error || !data.result) {
      return null;
    }

    const tx = data.result;
    const instructions = tx.transaction?.message?.instructions || [];
    
    for (const ix of instructions) {
      if (ix.programId === MEMO_PROGRAM_ID && ix.parsed) {
        try {
          const memoData = typeof ix.parsed === 'string' 
            ? JSON.parse(ix.parsed) 
            : ix.parsed;
          
          if (memoData.type === '2fa_secret' && 
              memoData.lookupKey === lookupKey) {
            return {
              type: '2fa_secret',
              lookupKey: memoData.lookupKey,
              encryptedData: memoData.encryptedData,
              txSignature: signature,
              timestamp: tx.blockTime || Date.now(),
            };
          }
        } catch (e) {
          continue;
        }
      }
    }

    return null;
  } catch (error) {
    console.error('[zk2fa] Error fetching memo from transaction:', error);
    return null;
  }
}

export async function searchMemosByLookupKey(
  lookupKey: string,
  walletAddress: string,
  config: StorageConfig
): Promise<SolanaMemoTransaction[]> {
  const heliusUrl = getHeliusUrl(config.helius);
  const results: SolanaMemoTransaction[] = [];

  try {
    const response = await fetch(heliusUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'getSignaturesForAddress',
        params: [walletAddress, { limit: 200 }],
      }),
      signal: AbortSignal.timeout(config.timeout || 15000),
    });

    const data = await response.json() as { result?: Array<{ signature: string }> };
    const signatures = data.result || [];

    for (const sig of signatures) {
      const txResponse = await fetch(heliusUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'getTransaction',
          params: [
            sig.signature,
            { encoding: 'jsonParsed', maxSupportedTransactionVersion: 0 }
          ],
        }),
      });

      const txData = await txResponse.json() as { result?: { blockTime?: number; slot?: number; transaction?: { message?: { instructions?: Array<{ programId: string; parsed?: unknown }> } } } };
      if (!txData.result) continue;

      const tx = txData.result;
      const instructions = tx.transaction?.message?.instructions || [];

      for (const ix of instructions) {
        if (ix.programId === MEMO_PROGRAM_ID) {
          const memoContent = typeof ix.parsed === 'string' ? ix.parsed : JSON.stringify(ix.parsed);
          
          if (memoContent.includes(lookupKey)) {
            results.push({
              signature: sig.signature,
              blockTime: tx.blockTime,
              memo: memoContent,
              slot: tx.slot,
            });
          }
        }
      }
    }

    return results;
  } catch (error) {
    console.error('[zk2fa] Error searching memos:', error);
    return [];
  }
}

export async function fetchFromIPFS(
  cid: string,
  gateways?: string[]
): Promise<string | null> {
  const gatewayList = gateways || [
    'https://ipfs.io/ipfs/',
    'https://cloudflare-ipfs.com/ipfs/',
    'https://gateway.pinata.cloud/ipfs/',
    'https://dweb.link/ipfs/',
  ];

  for (const gateway of gatewayList) {
    try {
      const url = `${gateway}${cid}`;
      const response = await fetch(url, {
        signal: AbortSignal.timeout(10000),
      });

      if (response.ok) {
        return await response.text();
      }
    } catch (error) {
      console.warn(`[zk2fa] IPFS gateway ${gateway} failed:`, error);
      continue;
    }
  }

  console.error('[zk2fa] All IPFS gateways failed for CID:', cid);
  return null;
}

export function parseTwoFAState(data: string): TwoFAState | null {
  try {
    const parsed = JSON.parse(data);
    
    if (typeof parsed.totpEnabled !== 'boolean') {
      console.error('[zk2fa] Invalid TwoFAState: missing totpEnabled');
      return null;
    }

    return {
      totpSecret: parsed.totpSecret || '',
      totpEnabled: parsed.totpEnabled,
      totpBackupCodes: parsed.totpBackupCodes || [],
      totpEnabledAt: parsed.totpEnabledAt || null,
      securityEmail: parsed.securityEmail,
      emailOtpEnabled: parsed.emailOtpEnabled,
      emailOtpEnabledAt: parsed.emailOtpEnabledAt,
    };
  } catch (error) {
    console.error('[zk2fa] Failed to parse TwoFAState:', error);
    return null;
  }
}

export async function get2FAStateFromChain(
  email: string,
  googleUserId: string,
  walletAddress: string,
  config: StorageConfig
): Promise<TwoFAState | null> {
  const lookupKey = derive2FALookupKeyClient(email, googleUserId);
  
  const pointer = await fetch2FAPointerFromSolana(
    lookupKey,
    walletAddress,
    config
  );

  if (!pointer) {
    return null;
  }

  return parseTwoFAState(pointer.encryptedData);
}

export function derive2FALookupKeyClient(email: string, googleUserId: string): string {
  const normalizedEmail = email.toLowerCase().trim();
  const input = `zkauth-lookup-v3-decentralized:${normalizedEmail}:2fa:lookup`;
  
  return `zkauth_2fa:${simpleHash(googleUserId + input)}`;
}

function simpleHash(input: string): string {
  let hash = 0;
  for (let i = 0; i < input.length; i++) {
    const char = input.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash;
  }
  
  const hashHex = Math.abs(hash).toString(16).padStart(16, '0');
  return hashHex.slice(0, 64).padEnd(64, '0');
}

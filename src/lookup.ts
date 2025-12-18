import { createHash, createHmac } from 'crypto';

const LOOKUP_NAMESPACE = 'zkauth-lookup-v3-decentralized';

/**
 * FULLY DECENTRALIZED LOOKUP KEY DERIVATION
 * 
 * All lookup keys are derived purely from user's Google OAuth credentials:
 * - googleUserId (Google's unique `sub` claim) - high entropy, user-specific
 * - email - normalized for consistency
 * 
 * NO SERVER-SIDE SECRETS REQUIRED
 * 
 * Security: 
 * - googleUserId is only available after OAuth consent (prevents enumeration)
 * - High entropy (128-bit random from Google) makes brute force infeasible
 * - Deterministic across server restarts
 */

export interface LookupKeys {
  starknetLookupKey: string;
  solanaLookupKey: string;
  zcashLookupKey: string;
  userId: string;
}

export interface ShareLookupKey {
  chain: 'starknet' | 'solana' | 'zcash';
  shareIndex: number;
  proofId: string;
  dataKey: string;
  ivKey: string;
  tagKey: string;
}

/**
 * HKDF-like key derivation using googleUserId as the key material.
 * This is fully decentralized - no server secrets needed.
 */
function deriveKey(googleUserId: string, email: string, purpose: string): string {
  const normalizedEmail = email.toLowerCase().trim();
  
  // Use googleUserId as HMAC key (it's high-entropy from Google)
  // The purpose and email provide domain separation
  const input = `${LOOKUP_NAMESPACE}:${normalizedEmail}:${purpose}`;
  return createHmac('sha256', googleUserId).update(input).digest('hex');
}

/**
 * Derive deterministic lookup keys from email + googleUserId.
 * 100% decentralized - no server salt needed.
 * googleUserId from Google OAuth provides enumeration protection.
 */
export function deriveLookupKeys(email: string, googleUserId: string): LookupKeys {
  const normalizedEmail = email.toLowerCase().trim();
  
  // Base hash for userId derivation
  const baseHash = deriveKey(googleUserId, normalizedEmail, 'base');
  const userId = `zkauth:${baseHash.substring(0, 16)}`;
  
  // Chain-specific lookup keys
  const starknetLookupKey = deriveKey(googleUserId, normalizedEmail, 'starknet:lookup');
  const solanaLookupKey = deriveKey(googleUserId, normalizedEmail, 'solana:lookup');
  const zcashLookupKey = deriveKey(googleUserId, normalizedEmail, 'zcash:lookup');
  
  return {
    starknetLookupKey,
    solanaLookupKey,
    zcashLookupKey,
    userId,
  };
}

export function deriveShareLookupKeys(
  email: string, 
  googleUserId: string
): ShareLookupKey[] {
  const normalizedEmail = email.toLowerCase().trim();
  
  const chains: Array<'starknet' | 'solana' | 'zcash'> = ['zcash', 'starknet', 'solana'];
  const result: ShareLookupKey[] = [];
  
  for (let i = 0; i < chains.length; i++) {
    const chain = chains[i];
    const shareIndex = i + 1;
    
    const proofId = deriveUuidFromGoogleId(googleUserId, normalizedEmail, `share:${shareIndex}:proof`);
    const dataKey = deriveUuidFromGoogleId(googleUserId, normalizedEmail, `share:${shareIndex}:data`);
    const ivKey = deriveUuidFromGoogleId(googleUserId, normalizedEmail, `share:${shareIndex}:iv`);
    const tagKey = deriveUuidFromGoogleId(googleUserId, normalizedEmail, `share:${shareIndex}:tag`);
    
    result.push({
      chain,
      shareIndex,
      proofId,
      dataKey,
      ivKey,
      tagKey,
    });
  }
  
  return result;
}

export function deriveEmailLookupKey(email: string, googleUserId: string): string {
  const normalizedEmail = email.toLowerCase().trim();
  return deriveUuidFromGoogleId(googleUserId, normalizedEmail, 'email:lookup');
}

function deriveUuidFromGoogleId(googleUserId: string, email: string, purpose: string): string {
  const hashResult = deriveKey(googleUserId, email, purpose);
  
  // Format as UUID v4-like string
  const uuid = [
    hashResult.substring(0, 8),
    hashResult.substring(8, 12),
    '4' + hashResult.substring(13, 16),
    ((parseInt(hashResult.substring(16, 18), 16) & 0x3f) | 0x80).toString(16).padStart(2, '0') + hashResult.substring(18, 20),
    hashResult.substring(20, 32),
  ].join('-');
  
  return uuid;
}

export function deriveUserId(email: string, googleUserId: string): string {
  const normalizedEmail = email.toLowerCase().trim();
  const hash = deriveKey(googleUserId, normalizedEmail, 'userid');
  return `zkauth:${hash.substring(0, 16)}`;
}

export function deriveSolanaMemoPrefix(email: string, googleUserId: string): string {
  const normalizedEmail = email.toLowerCase().trim();
  const hash = deriveKey(googleUserId, normalizedEmail, 'solana:memo');
  return `zkauth:${hash.substring(0, 12)}`;
}

/**
 * Derive 2FA-specific lookup key from email + googleUserId
 * This allows 2FA data to be stored and retrieved on-chain
 * Fully decentralized - no server salt needed
 */
export function derive2FALookupKey(email: string, googleUserId: string): string {
  const normalizedEmail = email.toLowerCase().trim();
  const hash = deriveKey(googleUserId, normalizedEmail, '2fa:lookup');
  return `zkauth_2fa:${hash}`;
}

// DEPRECATED: No longer needed - kept for backward compatibility during migration
// Will be removed in future version
export function initializeLookupSalt(_salt?: string): void {
  console.log('[zkAuth] initializeLookupSalt is deprecated - system is now fully decentralized');
  console.log('[zkAuth] Lookup keys are derived from Google OAuth credentials only');
}

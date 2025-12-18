/**
 * Decentralized Session Token System
 * 
 * Creates stateless, client-signed session tokens that:
 * 1. Are signed with user's Ed25519 key (derived from Google + Secret Phrase)
 * 2. Stored in localStorage (survives server restarts)
 * 3. Verified server-side against on-chain Poseidon commitment
 * 4. NO server secrets needed - 100% decentralized
 */

import * as nacl from 'tweetnacl';

export interface SessionTokenPayload {
  zkId: string;
  email: string;
  googleUserId: string;
  iat: number; // issued at (unix timestamp)
  exp: number; // expiry (unix timestamp)
}

export interface SessionToken {
  payload: SessionTokenPayload;
  signature: string; // hex-encoded Ed25519 signature
  publicKey: string; // hex-encoded Ed25519 public key for verification
}

/**
 * Create a session token signed with Ed25519 private key
 * Called client-side after successful authentication
 */
export function createSessionToken(
  payload: Omit<SessionTokenPayload, 'iat' | 'exp'>,
  privateKeyHex: string,
  expiryHours: number = 24 * 30 // 30 days default
): string {
  const now = Math.floor(Date.now() / 1000);
  const fullPayload: SessionTokenPayload = {
    ...payload,
    iat: now,
    exp: now + (expiryHours * 3600),
  };

  // Convert private key from hex to Uint8Array
  const privateKey = hexToBytes(privateKeyHex);
  
  // Generate keypair from seed (first 32 bytes of private key)
  const seed = privateKey.slice(0, 32);
  const keyPair = nacl.sign.keyPair.fromSeed(seed);
  
  // Create message to sign (JSON payload)
  const message = new TextEncoder().encode(JSON.stringify(fullPayload));
  
  // Sign the message
  const signature = nacl.sign.detached(message, keyPair.secretKey);
  
  // Create token object
  const token: SessionToken = {
    payload: fullPayload,
    signature: bytesToHex(signature),
    publicKey: bytesToHex(keyPair.publicKey),
  };
  
  // Encode as base64 for storage/transmission
  return btoa(JSON.stringify(token));
}

/**
 * Parse a session token (does NOT verify signature)
 * Use verifySessionToken for full verification
 */
export function parseSessionToken(tokenString: string): SessionToken | null {
  try {
    const decoded = atob(tokenString);
    return JSON.parse(decoded) as SessionToken;
  } catch {
    return null;
  }
}

/**
 * Verify a session token signature and expiry
 * Returns the payload if valid, null if invalid
 */
export function verifySessionToken(tokenString: string): SessionTokenPayload | null {
  try {
    const token = parseSessionToken(tokenString);
    if (!token) return null;
    
    // Check expiry
    const now = Math.floor(Date.now() / 1000);
    if (token.payload.exp < now) {
      console.log('[SessionToken] Token expired');
      return null;
    }
    
    // Verify signature
    const message = new TextEncoder().encode(JSON.stringify(token.payload));
    const signature = hexToBytes(token.signature);
    const publicKey = hexToBytes(token.publicKey);
    
    const isValid = nacl.sign.detached.verify(message, signature, publicKey);
    
    if (!isValid) {
      console.log('[SessionToken] Invalid signature');
      return null;
    }
    
    return token.payload;
  } catch (error) {
    console.error('[SessionToken] Verification error:', error);
    return null;
  }
}

/**
 * Extract public key from token for on-chain verification
 */
export function getTokenPublicKey(tokenString: string): string | null {
  const token = parseSessionToken(tokenString);
  return token?.publicKey ?? null;
}

/**
 * Check if token is expired
 */
export function isTokenExpired(tokenString: string): boolean {
  const token = parseSessionToken(tokenString);
  if (!token) return true;
  
  const now = Math.floor(Date.now() / 1000);
  return token.payload.exp < now;
}

/**
 * Get remaining time until token expiry (in seconds)
 */
export function getTokenTTL(tokenString: string): number {
  const token = parseSessionToken(tokenString);
  if (!token) return 0;
  
  const now = Math.floor(Date.now() / 1000);
  return Math.max(0, token.payload.exp - now);
}

// Helper functions
function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

// Storage key for localStorage
export const SESSION_TOKEN_KEY = 'zkterm_session_token';

/**
 * Store session token in localStorage
 */
export function storeSessionToken(token: string): void {
  if (typeof localStorage !== 'undefined') {
    localStorage.setItem(SESSION_TOKEN_KEY, token);
  }
}

/**
 * Get session token from localStorage
 */
export function getStoredSessionToken(): string | null {
  if (typeof localStorage !== 'undefined') {
    return localStorage.getItem(SESSION_TOKEN_KEY);
  }
  return null;
}

/**
 * Clear session token from localStorage
 */
export function clearSessionToken(): void {
  if (typeof localStorage !== 'undefined') {
    localStorage.removeItem(SESSION_TOKEN_KEY);
  }
}

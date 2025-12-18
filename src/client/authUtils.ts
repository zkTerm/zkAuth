/**
 * Shared authentication utilities for zkAuth dashboard
 * Contains localStorage auth, lookup key derivation, and other shared functions
 */

export const AUTH_STORAGE_KEY = 'zkterm_auth_user';

export interface GoogleUser {
  googleUserId: string;
  email: string;
  name: string;
  picture?: string;
  isRegistered: boolean;
  masterKeyDistributed?: boolean;
  verifiedAt?: string;
  lastSignIn?: string;
}

/**
 * Get stored user from localStorage (client-side session persistence)
 */
export function getStoredAuthUser(): GoogleUser | null {
  try {
    const stored = localStorage.getItem(AUTH_STORAGE_KEY);
    if (stored) {
      const parsed = JSON.parse(stored);
      if (parsed.googleUserId && parsed.email) {
        const now = new Date().toISOString();
        const user: GoogleUser = {
          googleUserId: parsed.googleUserId,
          email: parsed.email,
          name: parsed.name || parsed.email?.split('@')[0] || '',
          picture: parsed.picture,
          isRegistered: parsed.isRegistered ?? true,
          masterKeyDistributed: parsed.masterKeyDistributed ?? true,
          verifiedAt: parsed.verifiedAt || now,
          lastSignIn: parsed.lastSignIn || now,
        };
        if (!parsed.verifiedAt || !parsed.lastSignIn || !parsed.name) {
          localStorage.setItem(AUTH_STORAGE_KEY, JSON.stringify(user));
        }
        return user;
      }
    }
  } catch (e) {
    console.warn('[Auth] Failed to parse stored user:', e);
  }
  return null;
}

/**
 * Store user in localStorage for session persistence
 * Automatically sets verifiedAt (if not set) and lastSignIn timestamps
 */
export function storeAuthUser(user: GoogleUser): void {
  try {
    const existing = getStoredAuthUser();
    const now = new Date().toISOString();
    const userWithTimestamps: GoogleUser = {
      ...user,
      name: user.name || user.email?.split('@')[0] || '',
      verifiedAt: existing?.verifiedAt || user.verifiedAt || now,
      lastSignIn: now,
    };
    localStorage.setItem(AUTH_STORAGE_KEY, JSON.stringify(userWithTimestamps));
  } catch (e) {
    console.warn('[Auth] Failed to store user:', e);
  }
}

/**
 * Clear stored user from localStorage
 */
export function clearStoredAuthUser(): void {
  try {
    localStorage.removeItem(AUTH_STORAGE_KEY);
  } catch (e) {
    console.warn('[Auth] Failed to clear stored user:', e);
  }
}

/**
 * Update stored auth user flags (isRegistered, masterKeyDistributed)
 * Used after 2FA success to mark user as fully authenticated
 */
export function updateStoredAuthFlags(updates: Partial<Pick<GoogleUser, 'isRegistered' | 'masterKeyDistributed'>>): void {
  try {
    const stored = localStorage.getItem(AUTH_STORAGE_KEY);
    if (stored) {
      const parsed = JSON.parse(stored);
      const updated = { ...parsed, ...updates };
      localStorage.setItem(AUTH_STORAGE_KEY, JSON.stringify(updated));
      console.log('[Auth] Updated stored auth flags:', updates);
    }
  } catch (e) {
    console.warn('[Auth] Failed to update stored auth flags:', e);
  }
}

/**
 * Mask email for privacy: d*********a@gmail.com
 */
export function maskEmail(email: string): string {
  if (!email || !email.includes('@')) return email;
  const [local, domain] = email.split('@');
  if (local.length <= 2) {
    return `${'*'.repeat(local.length)}@${domain}`;
  }
  return `${local[0]}${'*'.repeat(local.length - 2)}${local[local.length - 1]}@${domain}`;
}

/**
 * Derive Ed25519 private key from Google credentials + secret phrase
 * Uses PBKDF2 with 100k iterations for key derivation
 */
export async function derivePrivateKey(googleUserId: string, secretPhrase: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(googleUserId + secretPhrase);
  
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    data,
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );
  
  const salt = encoder.encode("zkAuth-v1.9-ed25519-seed");
  
  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations: 100000,
      hash: "SHA-256",
    },
    keyMaterial,
    256
  );
  
  const seed = new Uint8Array(derivedBits);
  
  seed[0] &= 248;
  seed[31] &= 127;
  seed[31] |= 64;
  
  const privateKey = Array.from(seed)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
  
  return privateKey;
}

/**
 * Derive a lookup key from email and googleUserId using SHA-256
 * This key is used for localStorage storage and session validation
 */
export async function deriveLookupKey(email: string, googleUserId: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(email + googleUserId);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('').slice(0, 32);
}

/**
 * Generate localStorage key for 2FA data storage
 */
export function get2FALocalStorageKey(lookupKey: string): string {
  return `zkterm:2fa:local:${lookupKey}`;
}

/**
 * 2FA data structure stored in localStorage
 */
export interface TwoFALocalData {
  method?: 'totp' | 'email';
  verified?: boolean;
  verifiedAt?: number;
  disabled?: boolean;
  encryptedSecret?: string;
}

/**
 * Parse and validate 2FA data from localStorage
 */
export function parse2FAData(stored2FA: string | null): TwoFALocalData | null {
  if (!stored2FA) return null;
  try {
    return JSON.parse(stored2FA) as TwoFALocalData;
  } catch {
    return null;
  }
}

/**
 * Check if 2FA data is valid for session
 * Returns true if session has valid 2FA (either Email OTP or TOTP)
 */
export function isValid2FASession(data: TwoFALocalData | null): boolean {
  if (!data) return false;
  if (data.disabled) return false;
  
  if (data.method === 'email' && data.verified) {
    return true;
  }
  
  if (data.encryptedSecret) {
    return true;
  }
  
  return false;
}

/**
 * Store Email OTP 2FA marker after successful verification
 */
export async function storeEmailOTP2FAMarker(email: string, googleUserId: string): Promise<void> {
  const lookupKey = await deriveLookupKey(email, googleUserId);
  const localStorageKey = get2FALocalStorageKey(lookupKey);
  
  localStorage.setItem(localStorageKey, JSON.stringify({
    method: 'email',
    verified: true,
    verifiedAt: Date.now()
  }));
}

/**
 * Clear 2FA data from localStorage
 */
export async function clear2FAData(email: string, googleUserId: string): Promise<void> {
  const lookupKey = await deriveLookupKey(email, googleUserId);
  const localStorageKey = get2FALocalStorageKey(lookupKey);
  localStorage.removeItem(localStorageKey);
}

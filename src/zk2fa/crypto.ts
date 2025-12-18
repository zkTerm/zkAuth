import type { EncryptedTwoFAData } from './types';

const ALGORITHM = 'AES-GCM';
const KEY_LENGTH = 256;
const IV_LENGTH = 12;
const TAG_LENGTH = 128;

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

async function deriveKeyFromMasterKeyHash(masterKeyHash: string): Promise<globalThis.CryptoKey> {
  const keyMaterial = hexToBytes(masterKeyHash);
  
  if (keyMaterial.length !== 32) {
    const hashBuffer = await crypto.subtle.digest('SHA-256', hexToBytes(masterKeyHash));
    return crypto.subtle.importKey(
      'raw',
      hashBuffer,
      { name: ALGORITHM },
      false,
      ['encrypt', 'decrypt']
    );
  }
  
  return crypto.subtle.importKey(
    'raw',
    keyMaterial,
    { name: ALGORITHM },
    false,
    ['encrypt', 'decrypt']
  );
}

export async function encryptWithMasterKey(
  data: string,
  masterKeyHash: string
): Promise<EncryptedTwoFAData> {
  const key = await deriveKeyFromMasterKeyHash(masterKeyHash);
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const encoder = new TextEncoder();
  const encodedData = encoder.encode(data);

  const encrypted = await crypto.subtle.encrypt(
    {
      name: ALGORITHM,
      iv: iv,
      tagLength: TAG_LENGTH,
    },
    key,
    encodedData
  );

  const encryptedBytes = new Uint8Array(encrypted);
  const ciphertext = encryptedBytes.slice(0, -16);
  const tag = encryptedBytes.slice(-16);

  return {
    ciphertext: bytesToHex(ciphertext),
    iv: bytesToHex(iv),
    tag: bytesToHex(tag),
  };
}

export async function decryptWithMasterKey(
  encrypted: EncryptedTwoFAData,
  masterKeyHash: string
): Promise<string> {
  const key = await deriveKeyFromMasterKeyHash(masterKeyHash);
  const iv = hexToBytes(encrypted.iv);
  const ciphertext = hexToBytes(encrypted.ciphertext);
  const tag = hexToBytes(encrypted.tag);

  const combined = new Uint8Array(ciphertext.length + tag.length);
  combined.set(ciphertext);
  combined.set(tag, ciphertext.length);

  const decrypted = await crypto.subtle.decrypt(
    {
      name: ALGORITHM,
      iv: iv,
      tagLength: TAG_LENGTH,
    },
    key,
    combined
  );

  const decoder = new TextDecoder();
  return decoder.decode(decrypted);
}

export async function hashWithSHA256(data: string): Promise<string> {
  const encoder = new TextEncoder();
  const encodedData = encoder.encode(data);
  const hashBuffer = await crypto.subtle.digest('SHA-256', encodedData);
  return bytesToHex(new Uint8Array(hashBuffer));
}

export async function deriveEncryptionKey(
  masterKeyHash: string,
  salt: string
): Promise<string> {
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    hexToBytes(masterKeyHash),
    { name: 'HKDF' },
    false,
    ['deriveBits']
  );

  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: encoder.encode(salt),
      info: encoder.encode('zk2fa-encryption'),
    },
    keyMaterial,
    KEY_LENGTH
  );

  return bytesToHex(new Uint8Array(derivedBits));
}

export function generateRandomIV(): string {
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  return bytesToHex(iv);
}

export async function verifyBackupCode(
  code: string,
  hashedCodes: string[]
): Promise<boolean> {
  const normalizedCode = code.toUpperCase().replace(/[^A-Z0-9]/g, '');
  const codeHash = await hashWithSHA256(normalizedCode);
  return hashedCodes.includes(codeHash);
}

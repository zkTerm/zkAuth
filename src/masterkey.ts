import { createHash, randomBytes, createCipheriv, createDecipheriv } from 'crypto';
import type { MasterKey, EncryptionResult } from './types';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;
const TAG_LENGTH = 16;

export function generateMasterKey(): MasterKey {
  const keyBytes = randomBytes(32);
  const key = keyBytes.toString('hex');
  
  return {
    key,
    keyBytes,
    createdAt: Date.now()
  };
}

export function masterKeyFromHex(hex: string): MasterKey {
  const keyBytes = Buffer.from(hex, 'hex');
  if (keyBytes.length !== 32) {
    throw new Error('Invalid master key: must be 32 bytes (256-bit)');
  }
  
  return {
    key: hex,
    keyBytes,
    createdAt: Date.now()
  };
}

export function hashMasterKey(masterKey: MasterKey): string {
  return createHash('sha256').update(masterKey.keyBytes).digest('hex');
}

export function deriveEncryptionKey(pk: string): Buffer {
  return createHash('sha256').update(Buffer.from(pk, 'hex')).digest();
}

export function encryptWithPK(data: string, pk: string): EncryptionResult {
  const key = deriveEncryptionKey(pk);
  const iv = randomBytes(IV_LENGTH);
  
  const cipher = createCipheriv(ALGORITHM, key, iv);
  let ciphertext = cipher.update(data, 'utf8', 'hex');
  ciphertext += cipher.final('hex');
  
  const tag = cipher.getAuthTag();
  
  return {
    ciphertext,
    iv: iv.toString('hex'),
    tag: tag.toString('hex')
  };
}

export function decryptWithPK(encrypted: EncryptionResult, pk: string): string {
  const key = deriveEncryptionKey(pk);
  const iv = Buffer.from(encrypted.iv, 'hex');
  const tag = Buffer.from(encrypted.tag, 'hex');
  
  const decipher = createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(tag);
  
  let plaintext = decipher.update(encrypted.ciphertext, 'hex', 'utf8');
  plaintext += decipher.final('utf8');
  
  return plaintext;
}

export function encryptData(data: string, masterKey: MasterKey): EncryptionResult {
  const iv = randomBytes(IV_LENGTH);
  
  const cipher = createCipheriv(ALGORITHM, masterKey.keyBytes, iv);
  let ciphertext = cipher.update(data, 'utf8', 'hex');
  ciphertext += cipher.final('hex');
  
  const tag = cipher.getAuthTag();
  
  return {
    ciphertext,
    iv: iv.toString('hex'),
    tag: tag.toString('hex')
  };
}

export function decryptData(encrypted: EncryptionResult, masterKey: MasterKey): string {
  const iv = Buffer.from(encrypted.iv, 'hex');
  const tag = Buffer.from(encrypted.tag, 'hex');
  
  const decipher = createDecipheriv(ALGORITHM, masterKey.keyBytes, iv);
  decipher.setAuthTag(tag);
  
  let plaintext = decipher.update(encrypted.ciphertext, 'hex', 'utf8');
  plaintext += decipher.final('utf8');
  
  return plaintext;
}

export function generateUserId(pk: string): string {
  const hash = createHash('sha256').update(Buffer.from(pk, 'hex')).digest('hex');
  return `zkauth:${hash.substring(0, 16)}`;
}

import type { MasterKey, ShareData, EncryptedShare, SplitResult, ChainType } from './types';
import { encryptWithPK, decryptWithPK } from './masterkey';

const PRIME = BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617');

function mod(a: bigint, p: bigint = PRIME): bigint {
  const result = a % p;
  return result >= 0n ? result : result + p;
}

function modInverse(a: bigint, p: bigint = PRIME): bigint {
  let [old_r, r] = [a, p];
  let [old_s, s] = [1n, 0n];
  
  while (r !== 0n) {
    const quotient = old_r / r;
    [old_r, r] = [r, old_r - quotient * r];
    [old_s, s] = [s, old_s - quotient * s];
  }
  
  if (old_r !== 1n) {
    throw new Error('Modular inverse does not exist');
  }
  
  return mod(old_s, p);
}

function randomFieldElement(): bigint {
  const bytes = new Uint8Array(32);
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    crypto.getRandomValues(bytes);
  } else {
    const { randomBytes } = require('crypto');
    const buf = randomBytes(32);
    for (let i = 0; i < 32; i++) bytes[i] = buf[i];
  }
  
  let result = 0n;
  for (let i = 0; i < bytes.length; i++) {
    result = (result << 8n) + BigInt(bytes[i]);
  }
  return mod(result);
}

function evaluatePolynomial(coefficients: bigint[], x: bigint): bigint {
  let result = 0n;
  let xPower = 1n;
  
  for (const coeff of coefficients) {
    result = mod(result + mod(coeff * xPower));
    xPower = mod(xPower * x);
  }
  
  return result;
}

function lagrangeInterpolate(shares: Array<{ x: bigint; y: bigint }>): bigint {
  let secret = 0n;
  
  for (let i = 0; i < shares.length; i++) {
    let numerator = 1n;
    let denominator = 1n;
    
    for (let j = 0; j < shares.length; j++) {
      if (i !== j) {
        numerator = mod(numerator * mod(-shares[j].x));
        denominator = mod(denominator * mod(shares[i].x - shares[j].x));
      }
    }
    
    const lagrangeCoeff = mod(numerator * modInverse(denominator));
    secret = mod(secret + mod(shares[i].y * lagrangeCoeff));
  }
  
  return secret;
}

export function splitMasterKey(masterKey: MasterKey, threshold: number = 2, totalShares: number = 3): SplitResult {
  if (threshold < 2) {
    throw new Error('Threshold must be at least 2');
  }
  if (totalShares < threshold) {
    throw new Error('Total shares must be >= threshold');
  }
  if (totalShares > 255) {
    throw new Error('Maximum 255 shares supported');
  }
  
  const secret = BigInt('0x' + masterKey.key);
  
  const coefficients: bigint[] = [secret];
  for (let i = 1; i < threshold; i++) {
    coefficients.push(randomFieldElement());
  }
  
  const shares: ShareData[] = [];
  for (let i = 1; i <= totalShares; i++) {
    const x = BigInt(i);
    const y = evaluatePolynomial(coefficients, x);
    shares.push({ x: x.toString(), y: y.toString() });
  }
  
  return {
    shares,
    threshold,
    totalShares
  };
}

export function combineShares(shares: ShareData[]): string {
  if (shares.length < 2) {
    throw new Error('Need at least 2 shares to combine');
  }
  
  const parsedShares = shares.map(s => ({
    x: BigInt(s.x),
    y: BigInt(s.y)
  }));
  
  const xValues = new Set(parsedShares.map(s => s.x.toString()));
  if (xValues.size !== parsedShares.length) {
    throw new Error('Duplicate share indices detected');
  }
  
  const secret = lagrangeInterpolate(parsedShares);
  
  let hex = secret.toString(16);
  if (hex.length < 64) {
    hex = hex.padStart(64, '0');
  }
  
  return hex;
}

export function encryptShare(share: ShareData, shareIndex: number, chain: ChainType, pk: string): EncryptedShare {
  const shareJson = JSON.stringify(share);
  const encrypted = encryptWithPK(shareJson, pk);
  
  return {
    shareIndex,
    encryptedData: encrypted.ciphertext,
    iv: encrypted.iv,
    tag: encrypted.tag,
    chain,
    txHash: undefined,
    storageAddress: undefined
  };
}

export function decryptShare(encryptedShare: EncryptedShare, pk: string): ShareData {
  const decrypted = decryptWithPK({
    ciphertext: encryptedShare.encryptedData,
    iv: encryptedShare.iv,
    tag: encryptedShare.tag
  }, pk);
  
  return JSON.parse(decrypted);
}

export function getChainForShareIndex(index: number): ChainType {
  const chains: ChainType[] = ['zcash', 'starknet', 'solana'];
  return chains[(index - 1) % chains.length];
}

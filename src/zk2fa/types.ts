export interface TwoFAState {
  totpSecret: string;
  totpEnabled: boolean;
  totpBackupCodes: string[];
  totpEnabledAt: number | null;
  securityEmail?: string;
  emailOtpEnabled?: boolean;
  emailOtpEnabledAt?: number | null;
}

export interface TwoFAPointer {
  type: '2fa_secret';
  lookupKey: string;
  encryptedData: string;
  txSignature: string;
  timestamp: number;
}

export interface EncryptedTwoFAData {
  ciphertext: string;
  iv: string;
  tag: string;
}

export interface DecryptedTwoFAState extends TwoFAState {
  decryptedTotpSecret: string;
  decryptedSecurityEmail?: string;
}

export interface SolanaMemoTransaction {
  signature: string;
  blockTime: number | null;
  memo: string | null;
  slot: number;
}

export interface HeliusSearchResult {
  result: {
    signature: string;
    slot: number;
    blockTime: number;
  }[];
}

export interface IPFSGatewayConfig {
  gateway: string;
  timeout?: number;
}

export const DEFAULT_IPFS_GATEWAYS = [
  'https://ipfs.io/ipfs/',
  'https://cloudflare-ipfs.com/ipfs/',
  'https://gateway.pinata.cloud/ipfs/',
  'https://dweb.link/ipfs/',
];

export interface TwoFAVerificationResult {
  success: boolean;
  error?: string;
  method?: 'totp' | 'backup' | 'email';
}

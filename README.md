# @zkterm/zkauth v1.8.4

Cryptographic primitives for decentralized passwordless authentication with Shamir Secret Sharing.

## What This Package Provides

This package provides the **building blocks** for zkAuth:
- Lookup key derivation from Google OAuth credentials
- Master key generation and encryption/decryption
- Shamir 2-of-3 secret sharing
- Share encryption with Google credentials (dual-key architecture)

> **Note:** On-chain storage, registration flows, and 2FA are implemented in the zkTerm server, not in this package. This package provides the cryptographic primitives.

## Installation

```bash
npm install @zkterm/zkauth
```

## Core Concepts

### Dual-Key Architecture

The package implements a dual-key system:
1. **Wrapping Key** - Derived from Google OAuth credentials (email + googleUserId)
2. **Master Key** - The actual secret being protected

Shares are encrypted with the Wrapping Key, enabling:
- **Registration**: Secret Phrase used ONCE to generate Master Key
- **Login**: Google OAuth only (no phrase needed)

### Shamir 2-of-3

Master Key is split into 3 shares. Any 2 shares can reconstruct the original.

## API Reference

### Lookup Functions

```typescript
import { deriveLookupKeys, derive2FALookupKey } from '@zkterm/zkauth';

// From Google OAuth callback
const email = 'user@gmail.com';
const googleUserId = '123456789012345678901';

// Derive deterministic lookup keys - NO server secrets needed
const keys = deriveLookupKeys(email, googleUserId);
// {
//   starknetLookupKey: string,
//   solanaLookupKey: string,
//   zcashLookupKey: string,
//   userId: string
// }

// For 2FA data lookup
const twoFAKey = derive2FALookupKey(email, googleUserId);
```

### Master Key Functions

```typescript
import { 
  generateMasterKey, 
  hashMasterKey,
  encryptWithWrappingKey,
  decryptWithWrappingKey,
  deriveWrappingKey
} from '@zkterm/zkauth';

// Generate new 256-bit master key
const masterKey = generateMasterKey();

// Hash for verification
const hash = hashMasterKey(masterKey);

// Encrypt data with Google credentials
const encrypted = encryptWithWrappingKey(data, googleUserId, email);
// { ciphertext, iv, tag }

// Decrypt with same credentials
const decrypted = decryptWithWrappingKey(encrypted, googleUserId, email);
```

### Shamir Secret Sharing

```typescript
import { 
  splitMasterKey, 
  combineShares,
  encryptShareWithGoogle,
  decryptShareWithGoogle,
  getChainForShareIndex
} from '@zkterm/zkauth';

// Split master key into 3 shares (2 needed to reconstruct)
const { shares, threshold, totalShares } = splitMasterKey(masterKey, 2, 3);

// Encrypt each share with Google credentials
const encryptedShare = encryptShareWithGoogle(
  shares[0], 
  1, 
  'zcash', 
  googleUserId, 
  email
);

// Decrypt share
const decryptedShare = decryptShareWithGoogle(
  encryptedShare, 
  googleUserId, 
  email
);

// Reconstruct with any 2 shares
const reconstructedKey = combineShares([shares[0], shares[2]]);

// Get chain for share index
const chain = getChainForShareIndex(1); // 'zcash'
```

## Types

```typescript
interface LookupKeys {
  starknetLookupKey: string;
  solanaLookupKey: string;
  zcashLookupKey: string;
  userId: string;
}

interface MasterKey {
  key: string;           // 64-char hex (256-bit)
  keyBytes: Uint8Array;  // raw 32 bytes
  createdAt: number;     // unix timestamp
}

interface EncryptedShare {
  shareIndex: number;
  encryptedData: string;
  iv: string;
  tag: string;
  chain: 'zcash' | 'starknet' | 'solana';
  txHash?: string;
  storageAddress?: string;
}

interface ShareData {
  x: string;
  y: string;
}

interface EncryptionResult {
  ciphertext: string;
  iv: string;
  tag: string;
}
```

## Complete API

### Exports

```typescript
// Lookup
export { deriveLookupKeys, deriveShareLookupKeys, deriveEmailLookupKey, 
         deriveUserId, deriveSolanaMemoPrefix, derive2FALookupKey,
         initializeLookupSalt } from './lookup';

// Master Key
export { generateMasterKey, masterKeyFromHex, hashMasterKey,
         deriveEncryptionKey, encryptWithPK, decryptWithPK,
         encryptData, decryptData, generateUserId,
         deriveWrappingKey, encryptWithWrappingKey, 
         decryptWithWrappingKey } from './masterkey';

// Shamir Shares
export { splitMasterKey, combineShares, encryptShare, decryptShare,
         encryptShareWithGoogle, decryptShareWithGoogle,
         getChainForShareIndex } from './shares';

// Chain Storage (stub implementations)
export { ZcashShareStorage, StarknetShareStorage, 
         SolanaShareStorage } from './chains';

// Types
export type { ZkAuthConfig, MasterKey, EncryptedShare, ShareData,
              SplitResult, EncryptionResult, ChainType, 
              LookupKeys, ShareLookupKey } from './types';
```

## Security Properties

| Property | Description |
|----------|-------------|
| **No Server Secrets** | Lookup keys derived from Google OAuth only |
| **Deterministic** | Same credentials = same keys |
| **AES-256-GCM** | Authenticated encryption for shares |
| **Finite Field Math** | Shamir over 254-bit prime field |

## Changelog

### v1.8.4 (2024-12)
- Added `derive2FALookupKey` for 2FA data lookup
- Fully decentralized lookup key derivation (no server salt)
- Dual-key architecture with `encryptShareWithGoogle`/`decryptShareWithGoogle`
- Deprecated `initializeLookupSalt` (no-op for backwards compat)

### v1.0.0
- Initial release

## License

MIT

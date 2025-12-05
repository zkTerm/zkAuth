# @zkterm/zkauth

Privacy-first multi-chain authentication with Shamir Secret Sharing.

## Architecture

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                           zkAuth ARCHITECTURE                                 ║
║                    Privacy-First Multi-Chain Authentication                  ║
╚══════════════════════════════════════════════════════════════════════════════╝

┌─────────────────────────────────────────────────────────────────────────────┐
│  USER LAYER                                                                  │
│  └─ Login with Google / X (Twitter) via Web3Auth                            │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  AUTHENTICATION LAYER                                                        │
│  └─ Web3Auth → secp256k1 Private Key (PK)                                   │
│  └─ PK used to decrypt Master Key shares                                     │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  ENCRYPTION LAYER                                                            │
│  └─ zkTerm Master Key (256-bit)                                              │
│  └─ Split using Shamir Secret Sharing (2-of-3)                              │
│  └─ Each share encrypted with PK                                             │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    ▼               ▼               ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  BLOCKCHAIN STORAGE LAYER                                                    │
│                                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                       │
│  │    ZCASH     │  │   STARKNET   │  │    SOLANA    │                       │
│  │  (t-address) │  │   (Cairo)    │  │    (PDA)     │                       │
│  │   Share 1    │  │   Share 2    │  │   Share 3    │                       │
│  └──────────────┘  └──────────────┘  └──────────────┘                       │
│                                                                              │
│  Any 2 chains = reconstruct Master Key                                      │
│  1 chain down? Still works with other 2!                                    │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Installation

```bash
npm install @zkterm/zkauth
```

## Usage

### Initialize

```typescript
import { ZkAuth } from '@zkterm/zkauth';

const zkAuth = new ZkAuth({
  chains: {
    zcash: { rpcUrl: 'https://zcash-rpc.example.com' },
    starknet: { rpcUrl: 'https://starknet-rpc.example.com' },
    solana: { rpcUrl: 'https://api.mainnet-beta.solana.com' }
  },
  threshold: 2,    // 2-of-3
  totalShares: 3
});
```

### Register (First Time)

```typescript
// pk = Private Key from Web3Auth
const result = await zkAuth.register(pk);

console.log(result);
// {
//   success: true,
//   userId: 'zkauth:abc123...',
//   shares: [...],
//   masterKeyHash: '...'
// }
```

### Login (Returning User)

```typescript
const loginResult = await zkAuth.login(pk);

console.log(loginResult);
// {
//   success: true,
//   userId: 'zkauth:abc123...',
//   masterKey: { key: '...', keyBytes: Uint8Array, createdAt: ... },
//   sharesUsed: 2
// }
```

### Create Session

```typescript
const session = zkAuth.createSession(loginResult);

// Encrypt data
const encrypted = await session.encrypt('sensitive data');

// Decrypt data
const decrypted = await session.decrypt(encrypted);
```

### Direct Encryption

```typescript
const { masterKey } = loginResult;

// Encrypt
const encrypted = zkAuth.encrypt('my data', masterKey);

// Decrypt
const decrypted = zkAuth.decrypt(encrypted, masterKey);
```

## Flows

### Registration Flow

1. User login Google/X → Web3Auth → PK
2. Generate Master Key (random 256-bit)
3. Shamir split → 3 shares
4. Encrypt each share with PK
5. Store on 3 chains: Zcash, Starknet, Solana
6. User registered!

### Login Flow

1. User login Google/X → Web3Auth → PK
2. Fetch 2 encrypted shares from any 2 chains
3. Decrypt shares with PK
4. Shamir reconstruct (2-of-3)
5. Master Key ready!
6. Use for zkTerm encryption

## Security Properties

- **NO PASSWORD** - Social login only, no password to remember
- **NON-CUSTODIAL** - No single party holds full Master Key
- **FAULT TOLERANT** - 1 chain down? 2-of-3 still works
- **PRIVACY** - Encrypted shares, no plaintext on-chain
- **DECENTRALIZED** - 3 independent blockchains, no single point
- **RECOVERABLE** - Same social login = same PK = same Master Key
- **ZK-READY** - Master Key can generate STARK proofs

## API Reference

### ZkAuth Class

| Method | Description |
|--------|-------------|
| `register(pk)` | Register new user, split & store Master Key |
| `login(pk)` | Login existing user, reconstruct Master Key |
| `isRegistered(userId)` | Check if user is registered |
| `createSession(loginResult)` | Create session with encrypt/decrypt |
| `encrypt(data, masterKey)` | Encrypt data with Master Key |
| `decrypt(encrypted, masterKey)` | Decrypt data with Master Key |
| `getUserId(pk)` | Get user ID from PK |

### Types

```typescript
interface ZkAuthConfig {
  chains: {
    zcash?: ZcashConfig;
    starknet?: StarknetConfig;
    solana?: SolanaConfig;
  };
  threshold?: number;    // default: 2
  totalShares?: number;  // default: 3
}

interface MasterKey {
  key: string;           // hex string
  keyBytes: Uint8Array;  // raw bytes
  createdAt: number;     // timestamp
}

interface EncryptedShare {
  shareIndex: number;
  encryptedData: string;
  iv: string;
  chain: 'zcash' | 'starknet' | 'solana';
  txHash?: string;
  storageAddress?: string;
}
```

## License

MIT

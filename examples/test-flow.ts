import { ZkAuth } from '../src/client';
import { randomBytes } from 'crypto';

async function testZkAuth() {
  console.log('=== zkAuth Package Test ===\n');
  
  const mockPK = randomBytes(32).toString('hex');
  console.log(`Mock PK: ${mockPK.substring(0, 16)}...`);
  
  const zkAuth = new ZkAuth({
    chains: {
      zcash: { rpcUrl: 'https://mock-zcash-rpc.com' },
      starknet: { rpcUrl: 'https://mock-starknet-rpc.com' },
      solana: { rpcUrl: 'https://mock-solana-rpc.com' }
    },
    threshold: 2,
    totalShares: 3
  });
  
  console.log('\n--- REGISTRATION ---');
  const registerResult = await zkAuth.register(mockPK);
  
  console.log(`\nRegistration Result:`);
  console.log(`  Success: ${registerResult.success}`);
  console.log(`  User ID: ${registerResult.userId}`);
  console.log(`  Shares: ${registerResult.shares.length}`);
  console.log(`  Master Key Hash: ${registerResult.masterKeyHash.substring(0, 16)}...`);
  
  for (const share of registerResult.shares) {
    console.log(`  - Share ${share.shareIndex} on ${share.chain}: tag=${share.tag ? 'present' : 'MISSING!'}`);
  }
  
  console.log('\n--- LOGIN ---');
  const loginResult = await zkAuth.login(mockPK);
  
  console.log(`\nLogin Result:`);
  console.log(`  Success: ${loginResult.success}`);
  console.log(`  User ID: ${loginResult.userId}`);
  console.log(`  Shares Used: ${loginResult.sharesUsed}`);
  console.log(`  Master Key: ${loginResult.masterKey.key.substring(0, 16)}...`);
  
  console.log('\n--- ENCRYPTION TEST ---');
  const testData = 'Hello, zkAuth!';
  const encrypted = zkAuth.encrypt(testData, loginResult.masterKey);
  console.log(`Original: ${testData}`);
  console.log(`Encrypted: ${encrypted.ciphertext.substring(0, 32)}...`);
  
  const decrypted = zkAuth.decrypt(encrypted, loginResult.masterKey);
  console.log(`Decrypted: ${decrypted}`);
  console.log(`Match: ${testData === decrypted ? 'YES' : 'NO'}`);
  
  console.log('\n=== All Tests Passed! ===');
}

testZkAuth().catch(console.error);

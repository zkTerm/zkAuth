// @ts-ignore - no types available
import { buildPoseidon } from 'circomlibjs';
// @ts-ignore - no types available
import * as snarkjs from 'snarkjs';
import * as fs from 'fs';
import * as path from 'path';

export interface ZkAuthProof {
  proof: {
    pi_a: string[];
    pi_b: string[][];
    pi_c: string[];
    protocol: string;
    curve: string;
  };
  publicSignals: string[];
  commitment: string;
}

export interface ZkAuthProofInput {
  privateKeyHex: string;
}

let poseidon: any = null;
let vkey: any = null;

async function getPoseidon() {
  if (!poseidon) {
    poseidon = await buildPoseidon();
  }
  return poseidon;
}

function getCircuitPaths() {
  const circuitsDir = path.join(process.cwd(), 'circuits');
  return {
    wasm: path.join(circuitsDir, 'zkauth_identity_js', 'zkauth_identity.wasm'),
    zkey: path.join(circuitsDir, 'zkauth_identity_final.zkey'),
    vkey: path.join(circuitsDir, 'zkauth_identity_vkey.json')
  };
}

function getVKey() {
  if (!vkey) {
    const paths = getCircuitPaths();
    vkey = JSON.parse(fs.readFileSync(paths.vkey, 'utf8'));
  }
  return vkey;
}

/**
 * Split a 32-byte hex string into two 128-bit field elements
 */
function splitKeyTo128BitParts(keyHex: string): { low: bigint; high: bigint } {
  const keyBytes = Buffer.from(keyHex.replace('0x', ''), 'hex');
  if (keyBytes.length !== 32) {
    throw new Error('Key must be exactly 32 bytes');
  }
  
  const lowBytes = keyBytes.subarray(0, 16);
  const highBytes = keyBytes.subarray(16, 32);
  
  const low = BigInt('0x' + lowBytes.toString('hex'));
  const high = BigInt('0x' + highBytes.toString('hex'));
  
  return { low, high };
}

/**
 * Compute Poseidon commitment from private key
 * This commitment is stored on-chain during registration
 */
export async function computeCommitment(privateKeyHex: string): Promise<string> {
  const poseidonHash = await getPoseidon();
  const { low, high } = splitKeyTo128BitParts(privateKeyHex);
  
  const hash = poseidonHash([low, high]);
  const commitment = poseidonHash.F.toString(hash);
  
  return commitment;
}

/**
 * Generate zk proof that prover knows the private key
 * that hashes to the given commitment
 */
export async function generateProof(input: ZkAuthProofInput): Promise<ZkAuthProof> {
  const { privateKeyHex } = input;
  const paths = getCircuitPaths();
  
  if (!fs.existsSync(paths.wasm)) {
    throw new Error('Circuit WASM not found. Run circuit compilation first.');
  }
  if (!fs.existsSync(paths.zkey)) {
    throw new Error('Circuit zkey not found. Run trusted setup first.');
  }
  
  const { low, high } = splitKeyTo128BitParts(privateKeyHex);
  const commitment = await computeCommitment(privateKeyHex);
  
  const circuitInput = {
    private_key_low: low.toString(),
    private_key_high: high.toString(),
    commitment: commitment
  };
  
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    circuitInput,
    paths.wasm,
    paths.zkey
  );
  
  return {
    proof,
    publicSignals,
    commitment
  };
}

/**
 * Verify a zk proof
 */
export async function verifyProof(zkProof: ZkAuthProof): Promise<boolean> {
  const verificationKey = getVKey();
  
  const isValid = await snarkjs.groth16.verify(
    verificationKey,
    zkProof.publicSignals,
    zkProof.proof
  );
  
  return isValid;
}

/**
 * Verify that a proof matches a specific commitment
 */
export async function verifyProofForCommitment(
  zkProof: ZkAuthProof,
  expectedCommitment: string
): Promise<boolean> {
  if (zkProof.publicSignals[0] !== expectedCommitment) {
    return false;
  }
  
  return verifyProof(zkProof);
}

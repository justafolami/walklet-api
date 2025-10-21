import crypto from 'crypto';
import { Wallet } from 'ethers';

const ALG = 'aes-256-gcm';

// Ensure we have a proper 32-byte (64 hex chars) key in env
function getKey() {
  const hex = process.env.WALLET_ENCRYPTION_KEY || '';
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
    throw new Error(
      'WALLET_ENCRYPTION_KEY must be a 64-hex-character string (32 bytes).'
    );
  }
  return Buffer.from(hex, 'hex');
}

// Encrypt a hex private key (without 0x) using AES-256-GCM
function encryptHexPrivateKey(pkHex) {
  const key = getKey();
  const iv = crypto.randomBytes(12); // GCM recommends 12-byte IV
  const cipher = crypto.createCipheriv(ALG, key, iv);
  const ciphertext = Buffer.concat([
    cipher.update(Buffer.from(pkHex, 'hex')),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();
  return {
    ciphertext: ciphertext.toString('base64'),
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
    alg: ALG,
  };
}

// Create a fresh wallet and return address + encrypted private key bundle
export function createAndEncryptWallet() {
  const wallet = Wallet.createRandom();
  const pkHex = wallet.privateKey.replace(/^0x/, '');
  const enc = encryptHexPrivateKey(pkHex);
  return {
    address: wallet.address,
    ...enc,
  };
}
/**
 * Generate RSA Key Pair for JWT Signing
 *
 * Run this script with: npx ts-node scripts/generate-keys.ts
 *
 * This generates a 2048-bit RSA key pair for signing JWTs.
 * The private key is used to sign tokens, the public key is used to verify.
 */

import crypto from 'crypto';
import fs from 'fs';
import path from 'path';

const keysDir = path.join(process.cwd(), 'keys');

// Create keys directory if it doesn't exist
if (!fs.existsSync(keysDir)) {
  fs.mkdirSync(keysDir, { recursive: true });
}

// Generate RSA key pair (2048 bits)
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: {
    type: 'spki',
    format: 'pem',
  },
  privateKeyEncoding: {
    type: 'pkcs8',
    format: 'pem',
  },
});

// Save keys to files
const privateKeyPath = path.join(keysDir, 'private.pem');
const publicKeyPath = path.join(keysDir, 'public.pem');

fs.writeFileSync(privateKeyPath, privateKey);
fs.writeFileSync(publicKeyPath, publicKey);

console.log('🔐 RSA key pair generated successfully!');
console.log('');
console.log('Files created:');
console.log(`  Private key: ${privateKeyPath}`);
console.log(`  Public key:  ${publicKeyPath}`);
console.log('');
console.log('⚠️  IMPORTANT: Never commit these keys to version control!');
console.log('');
console.log('Add these to your .env file:');
console.log('');
console.log(`JWT_PRIVATE_KEY_PATH=${path.relative(process.cwd(), privateKeyPath)}`);
console.log(`JWT_PUBLIC_KEY_PATH=${path.relative(process.cwd(), publicKeyPath)}`);
console.log('');
console.log('Or set the keys directly as environment variables:');
console.log('');
console.log('JWT_PRIVATE_KEY="<contents of private.pem>"');
console.log('JWT_PUBLIC_KEY="<contents of public.pem>"');

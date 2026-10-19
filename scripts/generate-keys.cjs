const { generateKeyPairSync } = require('node:crypto');
const { existsSync, mkdirSync, writeFileSync } = require('node:fs');
const { resolve } = require('node:path');

const directory = resolve('keys');
const privatePath = resolve(directory, 'private.pem');
const publicPath = resolve(directory, 'public.pem');

if (existsSync(privatePath) || existsSync(publicPath)) {
  console.error('Keys already exist. Move them before generating a new pair.');
  process.exitCode = 1;
} else {
  const keys = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' },
  });
  mkdirSync(directory, { recursive: true });
  writeFileSync(privatePath, keys.privateKey, { flag: 'wx', mode: 0o600 });
  writeFileSync(publicPath, keys.publicKey, { flag: 'wx', mode: 0o644 });
  console.log('Created keys/private.pem and keys/public.pem. Keep private.pem secret.');
}

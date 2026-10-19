import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import {
  constants, createCipheriv, createDecipheriv, generateKeyPairSync,
  privateEncrypt, publicDecrypt, randomBytes,
} from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { BadRequestException } from '@nestjs/common';
import { NestExpressApplication } from '@nestjs/platform-express';
import { createApp } from '../src/app';
import { CryptoService, loadRsaKeys } from '../src/crypto.service';

const keys = generateKeyPairSync('rsa', { modulusLength: 2048 });
const otherKeys = generateKeyPairSync('rsa', { modulusLength: 2048 });
const service = new CryptoService(keys);

describe('CryptoService unit tests', () => {
  for (const [name, payload] of [
    ['empty', ''], ['ASCII', 'Hello NestJS'], ['Unicode', 'สวัสดี 世界 🔐'],
    ['2000 ASCII characters', 'a'.repeat(2000)],
    ['2000 emoji characters', '🔐'.repeat(2000)],
    ['control characters and BOM', '\uFEFF\u0000\n\r\t'],
  ]) {
    it(`round trips ${name}`, () => {
      const data = service.encrypt(payload);
      assert.deepEqual(service.decrypt(data.data1, data.data2), { payload });
    });
  }

  it('uses a fresh AES key and IV for each encryption', () => {
    const first = service.encrypt('same payload');
    const second = service.encrypt('same payload');
    assert.notEqual(first.data1, second.data1);
    assert.notEqual(first.data2, second.data2);
    assert.notDeepEqual(Buffer.from(first.data2, 'base64').subarray(0, 12), Buffer.from(second.data2, 'base64').subarray(0, 12));
  });

  it('matches the requested RSA direction and interoperates with Node crypto', () => {
    const data = service.encrypt('interoperable');
    const keyString = publicDecrypt({ key: keys.publicKey, padding: constants.RSA_PKCS1_PADDING }, Buffer.from(data.data1, 'base64')).toString('utf8');
    assert.match(keyString, /^[0-9a-f]{64}$/);
    const encrypted = Buffer.from(data.data2, 'base64');
    const decipher = createDecipheriv('aes-256-gcm', Buffer.from(keyString, 'hex'), encrypted.subarray(0, 12));
    decipher.setAuthTag(encrypted.subarray(12, 28));
    assert.equal(Buffer.concat([decipher.update(encrypted.subarray(28)), decipher.final()]).toString('utf8'), 'interoperable');
  });

  for (const [name, offset] of [['IV', 0], ['tag', 12], ['ciphertext', 28]] as const) {
    it(`rejects modified ${name}`, () => {
      const data = service.encrypt('tamper test');
      const bytes = Buffer.from(data.data2, 'base64');
      bytes[offset] ^= 1;
      assert.throws(() => service.decrypt(data.data1, bytes.toString('base64')), /INVALID_ENCRYPTED_DATA/);
    });
  }

  it('rejects mixed ciphertext/key pairs and keys from another RSA pair', () => {
    const first = service.encrypt('first');
    const second = service.encrypt('second');
    assert.throws(() => service.decrypt(first.data1, second.data2), /INVALID_ENCRYPTED_DATA/);
    const otherService = new CryptoService(otherKeys);
    assert.throws(() => otherService.decrypt(first.data1, first.data2), /INVALID_ENCRYPTED_DATA/);
  });

  it('rejects malformed, noncanonical, empty and truncated base64', () => {
    const valid = service.encrypt('hello');
    for (const data1 of ['', '!', 'YQ==', `${valid.data1}\n`]) {
      assert.throws(() => service.decrypt(data1, valid.data2), BadRequestException);
    }
    for (const data2 of ['', '!', 'YQ==', Buffer.alloc(27).toString('base64'), `${valid.data2}\n`, Buffer.alloc(8029).toString('base64')]) {
      assert.throws(() => service.decrypt(valid.data1, data2), BadRequestException);
    }
  });

  it('rejects an RSA-wrapped value that is not a 256-bit hex key', () => {
    const valid = service.encrypt('hello');
    const data1 = privateEncrypt({ key: keys.privateKey, padding: constants.RSA_PKCS1_PADDING }, Buffer.from('bad key')).toString('base64');
    assert.throws(() => service.decrypt(data1, valid.data2), /INVALID_ENCRYPTED_DATA/);
  });

  it('rejects authenticated but invalid UTF-8 and oversized plaintext from external clients', () => {
    const key = randomBytes(32);
    const data1 = privateEncrypt({ key: keys.privateKey, padding: constants.RSA_PKCS1_PADDING }, Buffer.from(key.toString('hex'))).toString('base64');
    for (const plaintext of [Buffer.from([0xff]), Buffer.from('a'.repeat(2001))]) {
      const iv = randomBytes(12);
      const cipher = createCipheriv('aes-256-gcm', key, iv);
      const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
      const data2 = Buffer.concat([iv, cipher.getAuthTag(), encrypted]).toString('base64');
      assert.throws(() => service.decrypt(data1, data2), /INVALID_ENCRYPTED_DATA/);
    }
  });
});

describe('HTTP API and RSA configuration', () => {
  let app: NestExpressApplication;
  let url: string;
  let directory: string;
  const originalPrivate = process.env.RSA_PRIVATE_KEY_PATH;
  const originalPublic = process.env.RSA_PUBLIC_KEY_PATH;

  before(async () => {
    directory = mkdtempSync(join(tmpdir(), 'primo-api-test-'));
    process.env.RSA_PRIVATE_KEY_PATH = join(directory, 'private.pem');
    process.env.RSA_PUBLIC_KEY_PATH = join(directory, 'public.pem');
    writeFileSync(process.env.RSA_PRIVATE_KEY_PATH, keys.privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
    writeFileSync(process.env.RSA_PUBLIC_KEY_PATH, keys.publicKey.export({ type: 'spki', format: 'pem' }));
    app = await createApp(false);
    await app.listen(0, '127.0.0.1');
    url = await app.getUrl();
  });

  after(async () => {
    await app?.close();
    if (directory) rmSync(directory, { recursive: true, force: true });
    if (originalPrivate === undefined) delete process.env.RSA_PRIVATE_KEY_PATH;
    else process.env.RSA_PRIVATE_KEY_PATH = originalPrivate;
    if (originalPublic === undefined) delete process.env.RSA_PUBLIC_KEY_PATH;
    else process.env.RSA_PUBLIC_KEY_PATH = originalPublic;
  });

  async function post(path: string, body: unknown) {
    const response = await fetch(`${url}${path}`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
    });
    return { status: response.status, body: await response.json() };
  }

  for (const payload of ['', 'Hello NestJS', '🔐'.repeat(2000)]) {
    it(`returns the exact response envelope and round trips ${[...payload].length} characters`, async () => {
      const encrypted = await post('/get-encrypt-data', { payload });
      assert.equal(encrypted.status, 200);
      assert.deepEqual(Object.keys(encrypted.body).sort(), ['data', 'error_code', 'successful']);
      assert.equal(encrypted.body.successful, true);
      assert.equal(encrypted.body.error_code, '');
      assert.deepEqual(Object.keys(encrypted.body.data).sort(), ['data1', 'data2']);
      const decrypted = await post('/get-decrypt-data', encrypted.body.data);
      assert.equal(decrypted.status, 200);
      assert.deepEqual(decrypted.body, { successful: true, error_code: '', data: { payload } });
    });
  }

  for (const [name, body] of [
    ['missing payload', {}], ['null payload', { payload: null }],
    ['numeric payload', { payload: 12 }], ['boolean payload', { payload: false }],
    ['array payload', { payload: [] }], ['object payload', { payload: {} }],
    ['2001 ASCII characters', { payload: 'a'.repeat(2001) }],
    ['2001 emoji characters', { payload: '🔐'.repeat(2001) }],
    ['unknown properties', { payload: 'ok', extra: true }],
    ['array request', []], ['null request', null],
  ]) {
    it(`rejects ${name}`, async () => {
      const response = await post('/get-encrypt-data', body);
      assert.equal(response.status, 400);
      assert.deepEqual(response.body, { successful: false, error_code: 'VALIDATION_ERROR', data: null });
    });
  }

  for (const [name, body] of [
    ['missing fields', {}], ['missing data2', { data1: 'YQ==' }],
    ['empty fields', { data1: '', data2: '' }],
    ['null fields', { data1: null, data2: null }],
    ['wrong types', { data1: 1, data2: [] }],
    ['invalid base64', { data1: '!', data2: '!' }],
    ['extra fields', { data1: 'YQ==', data2: 'YQ==', extra: 1 }],
  ]) {
    it(`rejects decrypt request with ${name}`, async () => {
      const response = await post('/get-decrypt-data', body);
      assert.equal(response.status, 400);
      assert.deepEqual(response.body, { successful: false, error_code: 'VALIDATION_ERROR', data: null });
    });
  }

  it('returns INVALID_ENCRYPTED_DATA for cryptographically invalid base64 inputs', async () => {
    const response = await post('/get-decrypt-data', { data1: 'YQ==', data2: 'YQ==' });
    assert.equal(response.status, 400);
    assert.deepEqual(response.body, { successful: false, error_code: 'INVALID_ENCRYPTED_DATA', data: null });
  });

  it('rejects modified ciphertext over HTTP', async () => {
    const data = service.encrypt('hello');
    const bytes = Buffer.from(data.data2, 'base64');
    bytes[28] ^= 1;
    const response = await post('/get-decrypt-data', { ...data, data2: bytes.toString('base64') });
    assert.equal(response.status, 400);
    assert.equal(response.body.error_code, 'INVALID_ENCRYPTED_DATA');
  });

  it('returns the error envelope for malformed JSON', async () => {
    const response = await fetch(`${url}/get-encrypt-data`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: '{',
    });
    assert.equal(response.status, 400);
    assert.deepEqual(await response.json(), { successful: false, error_code: 'VALIDATION_ERROR', data: null });
  });

  it('limits JSON bodies to 64 KiB', async () => {
    const response = await post('/get-encrypt-data', { payload: 'a'.repeat(65536) });
    assert.equal(response.status, 413);
    assert.deepEqual(response.body, { successful: false, error_code: 'PAYLOAD_TOO_LARGE', data: null });
  });

  it('returns the error envelope for unknown routes', async () => {
    const response = await fetch(`${url}/missing`);
    assert.equal(response.status, 404);
    assert.deepEqual(await response.json(), { successful: false, error_code: 'NOT_FOUND', data: null });
  });

  it('hides internal failure details', async () => {
    const instance = app.get(CryptoService);
    const original = instance.encrypt;
    try {
      instance.encrypt = () => { throw new Error('sensitive detail'); };
      const response = await post('/get-encrypt-data', { payload: 'test' });
      assert.equal(response.status, 500);
      assert.deepEqual(response.body, { successful: false, error_code: 'INTERNAL_ERROR', data: null });
    } finally {
      instance.encrypt = original;
    }
  });

  it('serves Swagger UI and its JavaScript assets', async () => {
    const response = await fetch(`${url}/api-docs`);
    assert.equal(response.status, 200);
    assert.match(await response.text(), /swagger-ui/);
    const script = await fetch(`${url}/api-docs/swagger-ui-init.js`);
    assert.equal(script.status, 200);
    assert.match(await script.text(), /get-encrypt-data/);
  });

  it('documents both endpoints, request limits, response schemas and errors', async () => {
    const response = await fetch(`${url}/api-docs-json`);
    assert.equal(response.status, 200);
    const document = await response.json();
    assert.deepEqual(Object.keys(document.paths).sort(), ['/get-decrypt-data', '/get-encrypt-data']);
    for (const path of Object.values(document.paths) as any[]) {
      assert.ok(path.post.requestBody.required);
      for (const status of ['200', '400', '413', '500']) assert.ok(path.post.responses[status]);
    }
    const schemas = document.components.schemas;
    assert.deepEqual(schemas.EncryptRequestDto.required, ['payload']);
    assert.equal(schemas.EncryptRequestDto.properties.payload.maxLength, 2000);
    assert.equal(schemas.EncryptRequestDto.properties.payload.minLength, 0);
    assert.deepEqual(schemas.DecryptRequestDto.required, ['data1', 'data2']);
    assert.equal(schemas.EncryptResponseDto.properties.data.nullable, true);
    assert.deepEqual(schemas.EncryptResponseDto.required, ['successful', 'error_code', 'data']);
  });

  it('loads matching PEM keys and fails on missing, mismatched, weak and non-RSA keys', () => {
    assert.ok(loadRsaKeys().publicKey.equals(keys.publicKey));
    const original = process.env.RSA_PUBLIC_KEY_PATH;
    const privateOriginal = process.env.RSA_PRIVATE_KEY_PATH;
    const alternatePublic = join(directory, 'alternate-public.pem');
    const alternatePrivate = join(directory, 'alternate-private.pem');
    try {
      process.env.RSA_PUBLIC_KEY_PATH = join(directory, 'missing.pem');
      assert.throws(loadRsaKeys, /Invalid RSA configuration/);
      process.env.RSA_PUBLIC_KEY_PATH = alternatePublic;
      writeFileSync(alternatePublic, otherKeys.publicKey.export({ type: 'pkcs1', format: 'pem' }));
      assert.throws(loadRsaKeys, /Invalid RSA configuration/);
      for (const pair of [
        generateKeyPairSync('rsa', { modulusLength: 1024 }),
        generateKeyPairSync('ec', { namedCurve: 'prime256v1' }),
      ]) {
        process.env.RSA_PRIVATE_KEY_PATH = alternatePrivate;
        writeFileSync(alternatePrivate, pair.privateKey.export({ type: 'pkcs8', format: 'pem' }));
        writeFileSync(alternatePublic, pair.publicKey.export({ type: 'spki', format: 'pem' }));
        assert.throws(loadRsaKeys, /Invalid RSA configuration/);
      }
    } finally {
      process.env.RSA_PUBLIC_KEY_PATH = original;
      process.env.RSA_PRIVATE_KEY_PATH = privateOriginal;
    }
  });
});

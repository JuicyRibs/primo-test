import { BadRequestException, Inject, Injectable } from '@nestjs/common';
import {
  constants, createCipheriv, createDecipheriv, createPrivateKey, createPublicKey,
  KeyObject, privateEncrypt, publicDecrypt, randomBytes,
} from 'node:crypto';
import { readFileSync } from 'node:fs';
import { DecryptedDataDto, EncryptedDataDto } from './dto';

export const RSA_KEYS = Symbol('RSA_KEYS');
export type RsaKeys = { privateKey: KeyObject; publicKey: KeyObject };

export function loadRsaKeys(): RsaKeys {
  try {
    const privateKey = createPrivateKey(readFileSync(process.env.RSA_PRIVATE_KEY_PATH ?? './keys/private.pem'));
    const publicKey = createPublicKey(readFileSync(process.env.RSA_PUBLIC_KEY_PATH ?? './keys/public.pem'));
    if (privateKey.asymmetricKeyType !== 'rsa' || publicKey.asymmetricKeyType !== 'rsa') {
      throw new Error('Keys must use RSA.');
    }
    if ((privateKey.asymmetricKeyDetails?.modulusLength ?? 0) < 2048) {
      throw new Error('RSA key must contain at least 2048 bits.');
    }
    if (!createPublicKey(privateKey).equals(publicKey)) {
      throw new Error('RSA keys must be a matching pair.');
    }
    return { privateKey, publicKey };
  } catch {
    throw new Error('Invalid RSA configuration. Set RSA_PRIVATE_KEY_PATH and RSA_PUBLIC_KEY_PATH to matching RSA PEM files (2048+ bits). For development, run npm run keys:generate.');
  }
}

@Injectable()
export class CryptoService {
  constructor(@Inject(RSA_KEYS) private readonly keys: RsaKeys) {}

  encrypt(payload: string): EncryptedDataDto {
    const keyString = randomBytes(32).toString('hex');
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', Buffer.from(keyString, 'hex'), iv);
    const ciphertext = Buffer.concat([cipher.update(payload, 'utf8'), cipher.final()]);
    const data1 = privateEncrypt(
      { key: this.keys.privateKey, padding: constants.RSA_PKCS1_PADDING },
      Buffer.from(keyString, 'ascii'),
    ).toString('base64');
    const data2 = Buffer.concat([iv, cipher.getAuthTag(), ciphertext]).toString('base64');
    return { data1, data2 };
  }

  decrypt(data1: string, data2: string): DecryptedDataDto {
    try {
      const wrappedKey = this.decodeBase64(data1);
      const encrypted = this.decodeBase64(data2);
      if (encrypted.length < 28 || encrypted.length > 8028) throw new Error('Invalid ciphertext length.');
      const keyString = publicDecrypt(
        { key: this.keys.publicKey, padding: constants.RSA_PKCS1_PADDING }, wrappedKey,
      ).toString('utf8');
      if (!/^[0-9a-f]{64}$/.test(keyString)) throw new Error('Invalid AES key.');
      const decipher = createDecipheriv('aes-256-gcm', Buffer.from(keyString, 'hex'), encrypted.subarray(0, 12));
      decipher.setAuthTag(encrypted.subarray(12, 28));
      const plaintext = Buffer.concat([decipher.update(encrypted.subarray(28)), decipher.final()]);
      const payload = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(plaintext);
      if ([...payload].length > 2000) throw new Error('Payload too long.');
      return { payload };
    } catch {
      throw new BadRequestException('INVALID_ENCRYPTED_DATA');
    }
  }

  private decodeBase64(value: string): Buffer {
    const decoded = Buffer.from(value, 'base64');
    if (!value || decoded.toString('base64') !== value) throw new Error('Invalid base64.');
    return decoded;
  }
}

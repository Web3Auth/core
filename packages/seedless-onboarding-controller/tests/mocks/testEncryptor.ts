import type {
  EncryptionKey,
  EncryptionResult,
  KeyDerivationOptions,
} from '@metamask/browser-passworder';
import { webcrypto } from 'node:crypto';

export default class TestEncryptor {
  DEFAULT_DERIVATION_PARAMS: KeyDerivationOptions = {
    algorithm: 'PBKDF2',
    params: {
      iterations: 10_000,
    },
  };

  DEFAULT_SALT = 'RANDOM_SALT';

  async importKey(keyString: string) {
    try {
      const parsedKey = JSON.parse(keyString);
      return webcrypto.subtle.importKey('jwk', parsedKey, 'AES-GCM', false, [
        'encrypt',
        'decrypt',
      ]);
    } catch (error) {
      console.error(error);
      throw new Error('Failed to import key');
    }
  }

  async keyFromPassword(
    password: string,
    salt: string = this.DEFAULT_SALT,
    exportable: boolean = true,
    opts: KeyDerivationOptions = this.DEFAULT_DERIVATION_PARAMS,
  ) {
    const passBuffer = Buffer.from(password);
    const saltBuffer = Buffer.from(salt, 'base64');

    const key = await webcrypto.subtle.importKey(
      'raw',
      passBuffer,
      { name: 'PBKDF2' },
      false,
      ['deriveBits', 'deriveKey'],
    );

    const encKey = await webcrypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: saltBuffer,
        iterations: opts.params.iterations,
        hash: 'SHA-256',
      },
      key,
      { name: 'AES-GCM', length: 256 },
      exportable,
      ['encrypt', 'decrypt'],
    );

    return encKey;
  }

  async encryptWithKey(
    encryptionKey: EncryptionKey | webcrypto.CryptoKey,
    data: unknown,
  ) {
    const dataString = JSON.stringify(data);
    const dataBuffer = Buffer.from(dataString);
    const vector = webcrypto.getRandomValues(new Uint8Array(16));

    const key = 'key' in encryptionKey ? encryptionKey.key : encryptionKey;
    const encBuff = await webcrypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: vector,
      },
      key,
      dataBuffer,
    );

    const buffer = new Uint8Array(encBuff);
    const vectorStr = Buffer.from(vector).toString('base64');
    const vaultStr = Buffer.from(buffer).toString('base64');
    const encryptionResult: EncryptionResult = {
      data: vaultStr,
      iv: vectorStr,
    };

    if ('derivationOptions' in encryptionKey) {
      encryptionResult.keyMetadata = encryptionKey.derivationOptions;
    }

    return encryptionResult;
  }

  async decryptWithKey(
    encryptionKey: EncryptionKey | webcrypto.CryptoKey,
    encData: EncryptionResult,
  ) {
    const encryptedData = Buffer.from(encData.data, 'base64');
    const vector = Buffer.from(encData.iv, 'base64');
    const key = 'key' in encryptionKey ? encryptionKey.key : encryptionKey;

    let decryptedObj;
    try {
      const result = await webcrypto.subtle.decrypt(
        { name: 'AES-GCM', iv: vector },
        key,
        encryptedData,
      );

      const decryptedData = new Uint8Array(result);
      const decryptedStr = Buffer.from(decryptedData).toString();
      decryptedObj = JSON.parse(decryptedStr);
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
    } catch (_e: unknown) {
      throw new Error('Failed to decrypt');
    }

    return decryptedObj;
  }
}

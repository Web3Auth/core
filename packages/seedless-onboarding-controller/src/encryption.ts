import { gcm } from '@noble/ciphers/aes';
import { bytesToUtf8 } from '@noble/ciphers/utils';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { randomBytes, utf8ToBytes } from '@noble/hashes/utils';

export class EncryptorDecryptor {
  readonly #HKDF_ENCRYPTION_KEY_INFO = 'encryption-key';

  readonly #nonceSize = 24;

  encrypt(key: string, data: string): string {
    const nonce = randomBytes(24);
    const rawKey = new Uint8Array(Buffer.from(key, 'base64'));
    const aes = gcm(rawKey, nonce);

    const rawData = utf8ToBytes(data);
    const cipherText = aes.encrypt(rawData);
    const encryptedData = Buffer.concat([nonce, cipherText]);
    return encryptedData.toString('base64');
  }

  decrypt(key: string, cipherTextCombinedWithNonceString: string): string {
    const rawKey = new Uint8Array(Buffer.from(key, 'base64'));
    const cipherTextCombinedWithNonce = new Uint8Array(
      Buffer.from(cipherTextCombinedWithNonceString, 'base64'),
    );

    const nonce = cipherTextCombinedWithNonce.slice(0, this.#nonceSize);
    const rawEncData = cipherTextCombinedWithNonce.slice(this.#nonceSize);

    const aes = gcm(rawKey, nonce);
    const rawData = aes.decrypt(rawEncData);

    return bytesToUtf8(rawData);
  }

  keyFromPassword(password: string): string {
    const seed = sha256(password);
    const key = hkdf(
      sha256,
      seed,
      undefined,
      this.#HKDF_ENCRYPTION_KEY_INFO,
      32,
    );
    return Buffer.from(key).toString('base64');
  }
}

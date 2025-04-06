import { gcm } from '@noble/ciphers/aes';
import { bytesToNumberBE } from '@noble/ciphers/utils';
import { secp256k1 } from '@noble/curves/secp256k1';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { randomBytes } from '@noble/hashes/utils';

import type { KeyPair } from './ToprfClient';

export class EncryptorDecryptor {
  readonly #HKDF_ENCRYPTION_KEY_INFO = 'encryption-key';

  readonly #HKDF_AUTH_KEY_INFO = 'authentication-key';

  readonly #nonceSize = 24;

  encrypt(key: Uint8Array, data: Uint8Array): string {
    const nonce = randomBytes(24);
    const aes = gcm(key, nonce);

    const cipherText = aes.encrypt(data);
    const encryptedData = Buffer.concat([nonce, cipherText]);
    return encryptedData.toString('base64');
  }

  decrypt(
    key: Uint8Array,
    cipherTextCombinedWithNonce: Uint8Array,
  ): Uint8Array {
    const nonce = cipherTextCombinedWithNonce.slice(0, this.#nonceSize);
    const rawEncData = cipherTextCombinedWithNonce.slice(this.#nonceSize);

    const aes = gcm(key, nonce);
    const rawData = aes.decrypt(rawEncData);

    return rawData;
  }

  keyFromPassword(password: string): Uint8Array {
    const seed = sha256(password);
    const key = hkdf(
      sha256,
      seed,
      undefined,
      this.#HKDF_ENCRYPTION_KEY_INFO,
      32,
    );
    return key;
  }

  authKeyPairFromPassword(password: string): KeyPair {
    const seed = sha256(password);
    const k = hkdf(sha256, seed, undefined, this.#HKDF_AUTH_KEY_INFO, 32); // Derive 256 bit key.

    // Converting from bytes to scalar like this is OK because statistical
    // distance between U(2^256) % secp256k1.n and U(secp256k1.n) is negligible.
    const sk = bytesToNumberBE(k) % secp256k1.CURVE.n;
    const pk = secp256k1.getPublicKey(sk, false);
    return { sk, pk };
  }
}

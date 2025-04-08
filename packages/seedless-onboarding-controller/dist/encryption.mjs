var __classPrivateFieldGet = (this && this.__classPrivateFieldGet) || function (receiver, state, kind, f) {
    if (kind === "a" && !f) throw new TypeError("Private accessor was defined without a getter");
    if (typeof state === "function" ? receiver !== state || !f : !state.has(receiver)) throw new TypeError("Cannot read private member from an object whose class did not declare it");
    return kind === "m" ? f : kind === "a" ? f.call(receiver) : f ? f.value : state.get(receiver);
};
var _EncryptorDecryptor_HKDF_ENCRYPTION_KEY_INFO, _EncryptorDecryptor_HKDF_AUTH_KEY_INFO, _EncryptorDecryptor_nonceSize;
import { gcm } from "@noble/ciphers/aes";
import { bytesToNumberBE } from "@noble/ciphers/utils";
import { secp256k1 } from "@noble/curves/secp256k1";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { randomBytes } from "@noble/hashes/utils";
export class EncryptorDecryptor {
    constructor() {
        _EncryptorDecryptor_HKDF_ENCRYPTION_KEY_INFO.set(this, 'encryption-key');
        _EncryptorDecryptor_HKDF_AUTH_KEY_INFO.set(this, 'authentication-key');
        _EncryptorDecryptor_nonceSize.set(this, 24);
    }
    encrypt(key, data) {
        const nonce = randomBytes(24);
        const aes = gcm(key, nonce);
        const cipherText = aes.encrypt(data);
        const encryptedData = Buffer.concat([nonce, cipherText]);
        return encryptedData.toString('base64');
    }
    decrypt(key, cipherTextCombinedWithNonce) {
        const nonce = cipherTextCombinedWithNonce.slice(0, __classPrivateFieldGet(this, _EncryptorDecryptor_nonceSize, "f"));
        const rawEncData = cipherTextCombinedWithNonce.slice(__classPrivateFieldGet(this, _EncryptorDecryptor_nonceSize, "f"));
        const aes = gcm(key, nonce);
        const rawData = aes.decrypt(rawEncData);
        return rawData;
    }
    keyFromPassword(password) {
        const seed = sha256(password);
        const key = hkdf(sha256, seed, undefined, __classPrivateFieldGet(this, _EncryptorDecryptor_HKDF_ENCRYPTION_KEY_INFO, "f"), 32);
        return key;
    }
    authKeyPairFromPassword(password) {
        const seed = sha256(password);
        const k = hkdf(sha256, seed, undefined, __classPrivateFieldGet(this, _EncryptorDecryptor_HKDF_AUTH_KEY_INFO, "f"), 32); // Derive 256 bit key.
        // Converting from bytes to scalar like this is OK because statistical
        // distance between U(2^256) % secp256k1.n and U(secp256k1.n) is negligible.
        const sk = bytesToNumberBE(k) % secp256k1.CURVE.n;
        const pk = secp256k1.getPublicKey(sk, false);
        return { sk, pk };
    }
}
_EncryptorDecryptor_HKDF_ENCRYPTION_KEY_INFO = new WeakMap(), _EncryptorDecryptor_HKDF_AUTH_KEY_INFO = new WeakMap(), _EncryptorDecryptor_nonceSize = new WeakMap();
//# sourceMappingURL=encryption.mjs.map
var __classPrivateFieldGet = (this && this.__classPrivateFieldGet) || function (receiver, state, kind, f) {
    if (kind === "a" && !f) throw new TypeError("Private accessor was defined without a getter");
    if (typeof state === "function" ? receiver !== state || !f : !state.has(receiver)) throw new TypeError("Cannot read private member from an object whose class did not declare it");
    return kind === "m" ? f : kind === "a" ? f.call(receiver) : f ? f.value : state.get(receiver);
};
var _EncryptorDecryptor_HKDF_ENCRYPTION_KEY_INFO, _EncryptorDecryptor_nonceSize;
import { gcm } from "@noble/ciphers/aes";
import { bytesToUtf8 } from "@noble/ciphers/utils";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { randomBytes, utf8ToBytes } from "@noble/hashes/utils";
export class EncryptorDecryptor {
    constructor() {
        _EncryptorDecryptor_HKDF_ENCRYPTION_KEY_INFO.set(this, 'encryption-key');
        _EncryptorDecryptor_nonceSize.set(this, 24);
    }
    encrypt(key, data) {
        const nonce = randomBytes(24);
        const rawKey = new Uint8Array(Buffer.from(key, 'base64'));
        const aes = gcm(rawKey, nonce);
        const rawData = utf8ToBytes(data);
        const cipherText = aes.encrypt(rawData);
        const encryptedData = Buffer.concat([nonce, cipherText]);
        return encryptedData.toString('base64');
    }
    decrypt(key, cipherTextCombinedWithNonceString) {
        const rawKey = new Uint8Array(Buffer.from(key, 'base64'));
        const cipherTextCombinedWithNonce = new Uint8Array(Buffer.from(cipherTextCombinedWithNonceString, 'base64'));
        const nonce = cipherTextCombinedWithNonce.slice(0, __classPrivateFieldGet(this, _EncryptorDecryptor_nonceSize, "f"));
        const rawEncData = cipherTextCombinedWithNonce.slice(__classPrivateFieldGet(this, _EncryptorDecryptor_nonceSize, "f"));
        const aes = gcm(rawKey, nonce);
        const rawData = aes.decrypt(rawEncData);
        return bytesToUtf8(rawData);
    }
    keyFromPassword(password) {
        const seed = sha256(password);
        const key = hkdf(sha256, seed, undefined, __classPrivateFieldGet(this, _EncryptorDecryptor_HKDF_ENCRYPTION_KEY_INFO, "f"), 32);
        return Buffer.from(key).toString('base64');
    }
}
_EncryptorDecryptor_HKDF_ENCRYPTION_KEY_INFO = new WeakMap(), _EncryptorDecryptor_nonceSize = new WeakMap();
//# sourceMappingURL=encryption.mjs.map
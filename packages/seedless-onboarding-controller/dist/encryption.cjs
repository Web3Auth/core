"use strict";
var __classPrivateFieldGet = (this && this.__classPrivateFieldGet) || function (receiver, state, kind, f) {
    if (kind === "a" && !f) throw new TypeError("Private accessor was defined without a getter");
    if (typeof state === "function" ? receiver !== state || !f : !state.has(receiver)) throw new TypeError("Cannot read private member from an object whose class did not declare it");
    return kind === "m" ? f : kind === "a" ? f.call(receiver) : f ? f.value : state.get(receiver);
};
var _EncryptorDecryptor_HKDF_ENCRYPTION_KEY_INFO, _EncryptorDecryptor_nonceSize;
Object.defineProperty(exports, "__esModule", { value: true });
exports.EncryptorDecryptor = void 0;
const aes_1 = require("@noble/ciphers/aes");
const utils_1 = require("@noble/ciphers/utils");
const hkdf_1 = require("@noble/hashes/hkdf");
const sha256_1 = require("@noble/hashes/sha256");
const utils_2 = require("@noble/hashes/utils");
class EncryptorDecryptor {
    constructor() {
        _EncryptorDecryptor_HKDF_ENCRYPTION_KEY_INFO.set(this, 'encryption-key');
        _EncryptorDecryptor_nonceSize.set(this, 24);
    }
    encrypt(key, data) {
        const nonce = (0, utils_2.randomBytes)(24);
        const rawKey = new Uint8Array(Buffer.from(key, 'base64'));
        const aes = (0, aes_1.gcm)(rawKey, nonce);
        const rawData = (0, utils_2.utf8ToBytes)(data);
        const cipherText = aes.encrypt(rawData);
        const encryptedData = Buffer.concat([nonce, cipherText]);
        return encryptedData.toString('base64');
    }
    decrypt(key, cipherTextCombinedWithNonceString) {
        const rawKey = new Uint8Array(Buffer.from(key, 'base64'));
        const cipherTextCombinedWithNonce = new Uint8Array(Buffer.from(cipherTextCombinedWithNonceString, 'base64'));
        const nonce = cipherTextCombinedWithNonce.slice(0, __classPrivateFieldGet(this, _EncryptorDecryptor_nonceSize, "f"));
        const rawEncData = cipherTextCombinedWithNonce.slice(__classPrivateFieldGet(this, _EncryptorDecryptor_nonceSize, "f"));
        const aes = (0, aes_1.gcm)(rawKey, nonce);
        const rawData = aes.decrypt(rawEncData);
        return (0, utils_1.bytesToUtf8)(rawData);
    }
    keyFromPassword(password) {
        const seed = (0, sha256_1.sha256)(password);
        const key = (0, hkdf_1.hkdf)(sha256_1.sha256, seed, undefined, __classPrivateFieldGet(this, _EncryptorDecryptor_HKDF_ENCRYPTION_KEY_INFO, "f"), 32);
        return Buffer.from(key).toString('base64');
    }
}
exports.EncryptorDecryptor = EncryptorDecryptor;
_EncryptorDecryptor_HKDF_ENCRYPTION_KEY_INFO = new WeakMap(), _EncryptorDecryptor_nonceSize = new WeakMap();
//# sourceMappingURL=encryption.cjs.map
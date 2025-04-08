import type { KeyPair } from "./ToprfClient.cjs";
export declare class EncryptorDecryptor {
    #private;
    encrypt(key: Uint8Array, data: Uint8Array): string;
    decrypt(key: Uint8Array, cipherTextCombinedWithNonce: Uint8Array): Uint8Array;
    keyFromPassword(password: string): Uint8Array;
    authKeyPairFromPassword(password: string): KeyPair;
}
//# sourceMappingURL=encryption.d.cts.map
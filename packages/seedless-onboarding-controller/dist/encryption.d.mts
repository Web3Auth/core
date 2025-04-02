export declare class EncryptorDecryptor {
    #private;
    encrypt(key: string, data: string): string;
    decrypt(key: string, cipherTextCombinedWithNonceString: string): string;
    keyFromPassword(password: string): string;
}
//# sourceMappingURL=encryption.d.mts.map
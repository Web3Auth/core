import type { KeyDerivationOptions, EncryptionKey, EncryptionResult } from "@metamask/browser-passworder";
export type OAuthVerifier = 'google' | 'apple';
export type AuthenticateUserParams = {
    idTokens: string[];
    verifier: OAuthVerifier;
    verifierID: string;
    indexes: number[];
    endpoints: string[];
};
export type NodeAuthToken = {
    /**
     * The token issued by the node on verifying the idToken
     */
    nodeAuthToken: string;
    /**
     * The index of the node that issued the token
     */
    nodeIndex: number;
};
export type NodeAuthTokens = NodeAuthToken[];
export type CreateSeedlessBackupParams = {
    password: string;
    seedPhrase: string;
};
export type RestoreSeedlessBackupParams = {
    nodeAuthTokens: NodeAuthTokens;
    password: string;
    seedPhrase: string;
};
export type Encryptor = {
    /**
     * @description Remove this method once the TOPRF lib is ready.
     * Encryption key should be generated using the TOPRF lib.
     * Generates a key from a password.
     *
     * @param password - The password to use for key generation.
     * @param salt - The salt to use for key generation.
     * @param exportable - Whether the key should be exportable.
     * @param opts - The options for key generation.
     * @returns A promise that resolves to the key.
     */
    keyFromPassword: (password: string, salt?: string, exportable?: boolean, opts?: KeyDerivationOptions) => Promise<CryptoKey | EncryptionKey>;
    /**
     * Encrypts a data string using a key.
     *
     * @param key - The key to use for encryption.
     * @param data - The data to encrypt.
     * @returns A promise that resolves to the encrypted data.
     */
    encryptWithKey: (key: CryptoKey | EncryptionKey, data: string) => Promise<EncryptionResult>;
    /**
     * Decrypts an encrypted data using a key.
     *
     * @param key - The key to use for decryption.
     * @param encryptedData - The encrypted data to decrypt.
     * @returns A promise that resolves to the decrypted data.
     */
    decryptWithKey: (key: CryptoKey | EncryptionKey, encryptedData: EncryptionResult) => Promise<string>;
    /**
     * Generates an encryption key from exported key string.
     *
     * @param key - The exported key string.
     * @returns The encryption key.
     */
    importKey: (key: string) => Promise<CryptoKey | EncryptionKey>;
    /**
     * Exports a key to an exported key string.
     *
     * @param key - The key to export.
     * @returns The exported key string.
     */
    exportKey: (key: CryptoKey | EncryptionKey) => Promise<string>;
    /**
     * Generates a random salt.
     *
     * @returns the random salt string.
     */
    generateSalt?: () => string;
};
//# sourceMappingURL=types.d.mts.map
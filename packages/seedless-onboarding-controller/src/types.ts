import type { Json } from '@metamask/utils';

export type OAuthVerifier = 'google' | 'apple';

export type UpdatePasswordParams = {
  verifier: OAuthVerifier;
  verifierID: string;
  newPassword: string;
  oldPassword: string;
};

/**
 * @description Encryptor interface for encrypting and decrypting seedless onboarding vault.
 */
export type Encryptor = {
  /**
   * Encrypts the given object with the given password.
   *
   * @param password - The password to encrypt with.
   * @param object - The object to encrypt.
   * @returns The encrypted string.
   */
  encrypt: (password: string, object: Json) => Promise<string>;
  /**
   * Decrypts the given encrypted string with the given password.
   *
   * @param password - The password to decrypt with.
   * @param encryptedString - The encrypted string to decrypt.
   * @returns The decrypted object.
   */
  decrypt: (password: string, encryptedString: string) => Promise<unknown>;
};

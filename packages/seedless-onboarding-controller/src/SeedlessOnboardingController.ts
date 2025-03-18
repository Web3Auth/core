import type {
  ControllerGetStateAction,
  RestrictedMessenger,
  StateMetadata,
} from '@metamask/base-controller';
import { BaseController } from '@metamask/base-controller';
import type {
  EncryptionKey,
  EncryptionResult,
  KeyDerivationOptions,
} from '@metamask/browser-passworder';
import {
  encryptWithKey,
  decryptWithKey,
  keyFromPassword,
  generateSalt,
} from '@metamask/browser-passworder';
import type {
  KeyringControllerState,
  KeyringControllerStateChangeEvent,
} from '@metamask/keyring-controller';

import type {
  CreateSeedlessBackupParams,
  OAuthParams,
  OAuthVerifier,
  RestoreSeedlessBackupParams,
} from './types';

const controllerName = 'SeedlessOnboardingController';

// State
// eslint-disable-next-line @typescript-eslint/no-empty-object-type
export type SeedlessOnboardingControllerState = {};

// Actions
export type SeedlessOnboardingControllerGetStateActions =
  ControllerGetStateAction<
    typeof controllerName,
    SeedlessOnboardingControllerState
  >;

export type AllowedEvents = KeyringControllerStateChangeEvent;
export type AllowedActions = SeedlessOnboardingControllerGetStateActions;

export const defaultState: SeedlessOnboardingControllerState = {};
const metadata: StateMetadata<SeedlessOnboardingControllerState> = {};

// Messenger
export type SeedlessOnboardingControllerMessenger = RestrictedMessenger<
  typeof controllerName,
  AllowedActions,
  AllowedEvents,
  AllowedActions['type'],
  AllowedEvents['type']
>;

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
  keyFromPassword: (
    password: string,
    salt?: string,
    exportable?: boolean,
    opts?: KeyDerivationOptions,
  ) => Promise<CryptoKey | EncryptionKey>;

  /**
   * Encrypts a data string using a key.
   *
   * @param key - The key to use for encryption.
   * @param data - The data to encrypt.
   * @returns A promise that resolves to the encrypted data.
   */
  encryptWithKey: (
    key: CryptoKey | EncryptionKey,
    data: string,
  ) => Promise<EncryptionResult>;

  /**
   * Decrypts an encrypted data using a key.
   *
   * @param key - The key to use for decryption.
   * @param encryptedData - The encrypted data to decrypt.
   * @returns A promise that resolves to the decrypted data.
   */
  decryptWithKey: (
    key: CryptoKey | EncryptionKey,
    encryptedData: EncryptionResult,
  ) => Promise<string>;

  /**
   * Generates a random salt.
   *
   * @returns the random salt string.
   */
  generateSalt?: () => string;
};

export type SeedlessOnboardingControllerOptions = {
  messenger: SeedlessOnboardingControllerMessenger;

  /**
   * @description Encryptor used for encryption and decryption of data.
   * @default WebCryptoAPI
   */
  encryptor?: Encryptor;
};

export class SeedlessOnboardingController extends BaseController<
  typeof controllerName,
  SeedlessOnboardingControllerState,
  SeedlessOnboardingControllerMessenger
> {
  readonly #encryptor: Encryptor = {
    keyFromPassword: (password, salt, exportable, opts) => {
      const randomSalt = salt || Math.random().toString(36).substring(2, 15);
      return keyFromPassword(password, randomSalt, exportable, opts);
    },
    encryptWithKey,
    decryptWithKey,
    generateSalt,
  };

  constructor({ messenger, encryptor }: SeedlessOnboardingControllerOptions) {
    super({
      messenger,
      metadata,
      name: controllerName,
      state: { ...defaultState },
    });
    if (encryptor) {
      this.#encryptor = encryptor;
    }
    this.#subscribeToMessageEvents();
  }

  /**
   * @description Backup seed phrase using the seedless onboarding flow.
   * @param params - The parameters for backup seed phrase.
   * @param params.idToken - The ID token from Social login
   * @param params.verifier - OAuth verifier
   * @param params.verifierId - user email or id from Social login
   * @param params.password - The password used to create new wallet and seedphrase
   * @param params.seedPhrase - The seed phrase to backup
   * @returns A promise that resolves to the encrypted seed phrase.
   */
  async backupSeedPhrase({
    idToken,
    verifier,
    verifierId,
    password,
    seedPhrase,
  }: CreateSeedlessBackupParams): Promise<string> {
    // handle OPRF and generate EK -> signing key pair
    const ek = await this.createEncryptionKey({
      idToken,
      verifier,
      verifierId,
      password,
    });
    // encrypt SRP with EK and store on metadata service
    const encryptedSRP = await this.#encryptSeedPhrase(ek, seedPhrase);
    // store encryptedSRP on metadata service
    await this.storeEncryptedSRP({
      idToken,
      verifier,
      verifierId,
      encryptedSRP,
    });

    return encryptedSRP;
  }

  /**
   * @description Restore seed phrase using the seedless onboarding flow.
   * @param params - The parameters for restore seed phrase.
   * @param params.idToken - The ID token from Social login
   * @param params.password - The password used to create new wallet and seedphrase
   * @param params.verifier - OAuth verifier
   * @param params.verifierId - user email or id from Social login
   * @returns A promise that resolves to the seed phrase.
   */
  async restoreSRP({
    idToken,
    password,
    verifier,
    verifierId,
  }: RestoreSeedlessBackupParams): Promise<string> {
    // fetch encrypted SRP from metadata service using EK
    const encryptedSRP = await this.fetchEncryptedSRP({
      idToken,
      verifier,
      verifierId,
    });
    // handle OPRF and restore EK
    const ek = await this.createEncryptionKey({
      idToken,
      verifier,
      verifierId,
      password,
    });
    // decrypt SRP
    const srp = await this.#decryptSeedPhrase(ek, encryptedSRP);
    return srp;
  }

  /**
   * Creates an encryption key with TOPRF and given parameters.
   *
   * @param _params - The parameters for creating the encryption key.
   * @param _params.idToken - The ID token from Social login
   * @param _params.verifier - OAuth verifier
   * @param _params.verifierId - user email or id from Social login
   * @param _params.password - The password used to create new wallet and seedphrase
   * @returns A promise that resolves to the stringified encryption key.
   */
  async createEncryptionKey({
    password,
  }: {
    idToken: string;
    verifier: OAuthVerifier;
    verifierId: string;
    password: string;
  }): Promise<CryptoKey | EncryptionKey> {
    // TODO: this is MOCK implementation
    // replace with actual implementation once the backend is ready
    const key = await this.#encryptor.keyFromPassword(password);
    return key;
  }

  async storeEncryptedSRP(_params: {
    idToken: string;
    verifier: string;
    verifierId: string;
    encryptedSRP: string;
  }) {
    // store encrypted SRP on metadata service
  }

  async fetchEncryptedSRP(_params: OAuthParams): Promise<string> {
    // fetch encrypted SRP from metadata service
    return '';
  }

  async #encryptSeedPhrase(
    encryptionKey: CryptoKey | EncryptionKey,
    seedPhrase: string,
  ): Promise<string> {
    const encryptedResult = await this.#encryptor.encryptWithKey(
      encryptionKey,
      seedPhrase,
    );

    return JSON.stringify(encryptedResult);
  }

  async #decryptSeedPhrase(
    decryptionKey: CryptoKey | EncryptionKey,
    encryptedSRP: string,
  ): Promise<string> {
    let encryptedResult: EncryptionResult;
    try {
      encryptedResult = JSON.parse(encryptedSRP) as EncryptionResult;
    } catch (error: unknown) {
      console.error(error);
      throw new Error('Fail to encrypt. Invalid data');
    }

    const decryptedResult = await this.#encryptor.decryptWithKey(
      decryptionKey,
      encryptedResult,
    );

    return decryptedResult as string;
  }

  #handleKeyringStateChange(_keyringState: KeyringControllerState) {
    // handle keyring state change
    // Actions to perform when keyring state changes
    // 1. when the existing keyring is removed,
    // 2. when the new keyring is added
    // 3. when more than one keyring is added
  }

  /**
   * Constructor helper for subscribing to message events.
   */
  #subscribeToMessageEvents() {
    this.messagingSystem.subscribe(
      'KeyringController:stateChange',
      (keyringState) => this.#handleKeyringStateChange(keyringState),
    );
  }
}

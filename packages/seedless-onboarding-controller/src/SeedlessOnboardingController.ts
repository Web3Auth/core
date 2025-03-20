import type {
  ControllerGetStateAction,
  RestrictedMessenger,
  StateMetadata,
} from '@metamask/base-controller';
import { BaseController } from '@metamask/base-controller';
import {
  encryptWithKey,
  decryptWithKey,
  keyFromPassword,
  generateSalt,
  importKey,
  exportKey,
} from '@metamask/browser-passworder';
import type {
  KeyringControllerState,
  KeyringControllerStateChangeEvent,
} from '@metamask/keyring-controller';

import { ToprfAuthClient } from './ToprfClient';
import type {
  AuthenticateUserParams,
  CreateSeedlessBackupParams,
  Encryptor,
  NodeAuthTokens,
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
const seedlessOnboardingMetadata: StateMetadata<SeedlessOnboardingControllerState> =
  {};

// Messenger
export type SeedlessOnboardingControllerMessenger = RestrictedMessenger<
  typeof controllerName,
  AllowedActions,
  AllowedEvents,
  AllowedActions['type'],
  AllowedEvents['type']
>;

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
    importKey,
    exportKey,
  };

  readonly #toprfAuthClient: ToprfAuthClient;

  constructor({ messenger, encryptor }: SeedlessOnboardingControllerOptions) {
    super({
      messenger,
      metadata: seedlessOnboardingMetadata,
      name: controllerName,
      state: { ...defaultState },
    });
    if (encryptor) {
      this.#encryptor = encryptor;
    }
    this.#toprfAuthClient = new ToprfAuthClient(this.#encryptor);
    this.#subscribeToMessageEvents();
  }

  /**
   * @description Authenticate OAuth user using the seedless onboarding flow
   * and determine if the user is already registered or not.
   * @param params - The parameters for authenticate OAuth user.
   * @param params.idToken - The ID token from Social login
   * @param params.verifier - OAuth verifier
   * @param params.verifierId - user email or id from Social login
   * @returns A promise that resolves to the authentication result.
   */
  async authenticateOAuthUser(params: AuthenticateUserParams) {
    const verificationResult = await this.#toprfAuthClient.authenticate(params);
    return verificationResult;
  }

  /**
   * @description Backup seed phrase using the seedless onboarding flow.
   * @param params - The parameters for backup seed phrase.
   * @param params.password - The password used to create new wallet and seedphrase
   * @param params.nodeAuthTokens - The node auth tokens reterieved from the OAuth Authentication
   * @param params.seedPhrase - The seed phrase to backup
   * @returns A promise that resolves to the encrypted seed phrase and the encryption key.
   */
  async createSeedPhraseBackup({
    nodeAuthTokens,
    password,
    seedPhrase,
  }: CreateSeedlessBackupParams): Promise<{
    encryptedSeedPhrase: string;
    encryptionKey: string;
  }> {
    const { encKey } = await this.#toprfAuthClient.createEncKey({
      nodeAuthTokens,
      password,
    });

    const storeResult = await this.#toprfAuthClient.storeSecretData({
      nodeAuthTokens,
      encKey,
      secretData: seedPhrase,
    });

    return {
      encryptedSeedPhrase: storeResult.encryptedSecretData,
      encryptionKey: storeResult.encKey,
    };
  }

  /**
   * @description Fetch seed phrase metadata from the metadata store.
   * @param nodeAuthTokens - The node auth tokens reterieved from the OAuth Authentication
   * @param password - The password used to create new wallet and seedphrase
   * @returns A promise that resolves to the seed phrase metadata.
   */
  async fetchAndRestoreSeedPhraseMetadata(
    nodeAuthTokens: NodeAuthTokens,
    password: string,
  ) {
    const { encKey, secretData } = await this.#toprfAuthClient.fetchSecretData({
      nodeAuthTokens,
      password,
    });

    return {
      encryptedSeedPhrase: secretData,
      encryptionKey: encKey,
    };
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

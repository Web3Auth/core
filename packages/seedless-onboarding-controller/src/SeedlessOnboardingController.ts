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
export type SeedlessOnboardingControllerState = {
  /**
   * The node auth tokens from OAuth User authentication after the Social login.
   *
   * This values are used to authenticate users when they go through the Seedless Onboarding flow.
   */
  nodeAuthTokens?: NodeAuthTokens;
  /**
   * Indicates whether the user has already fully/partially completed the Seedless Onboarding flow.
   *
   * An encryption key is generated from user entered password using Threshold OPRF and the seed phrase is encrypted with the key.
   * During the Seedless Onboarding Authentication step, TOPRF services check whether user has already generated the encryption key.
   *
   * If this value is `true`, we can assume that user already has completed the `SeedPhrase` generation step, and user will have to
   * fetch the `SeedPhrase` with correct password. Otherwise, users will be asked to set up seedphrase and password, first.
   */
  hasValidEncryptionKey?: boolean;
};

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
  {
    nodeAuthTokens: {
      persist: true,
      anonymous: false,
    },
    hasValidEncryptionKey: {
      persist: true,
      anonymous: false,
    },
  };

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
      const exportableKey = exportable ?? true;
      return keyFromPassword(password, randomSalt, exportableKey, opts);
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
    this.update((state) => {
      state.nodeAuthTokens = verificationResult.nodeAuthTokens;
      state.hasValidEncryptionKey = verificationResult.hasValidEncKey;
    });
    return verificationResult;
  }

  /**
   * @description Backup seed phrase using the seedless onboarding flow.
   * @param params - The parameters for backup seed phrase.
   * @param params.password - The password used to create new wallet and seedphrase
   * @param params.seedPhrase - The seed phrase to backup
   * @returns A promise that resolves to the encrypted seed phrase and the encryption key.
   */
  async createSeedPhraseBackup({
    password,
    seedPhrase,
  }: CreateSeedlessBackupParams): Promise<{
    encryptedSeedPhrase: string;
    encryptionKey: string;
  }> {
    const nodeAuthTokens = this.#getNodeAuthTokens();
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
   * @param password - The password used to create new wallet and seedphrase
   * @returns A promise that resolves to the seed phrase metadata.
   */
  async fetchAndRestoreSeedPhraseMetadata(password: string) {
    const nodeAuthTokens = this.#getNodeAuthTokens();
    const { encKey, secretData } = await this.#toprfAuthClient.fetchSecretData({
      nodeAuthTokens,
      password,
    });

    return {
      encryptedSeedPhrase: secretData,
      encryptionKey: encKey,
    };
  }

  #getNodeAuthTokens() {
    const { nodeAuthTokens } = this.state;
    if (!nodeAuthTokens) {
      // TODO: create standard errors
      throw new Error('Node auth tokens not found');
    }
    return nodeAuthTokens;
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

import type {
  ControllerGetStateAction,
  ControllerStateChangeEvent,
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
import type { KeyringControllerStateChangeEvent } from '@metamask/keyring-controller';

import { SeedlessOnboardingControllerError } from './constants';
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

export type AllowedActions = SeedlessOnboardingControllerGetStateActions;

export type SeedlessOnboardingControllerStateChangeEvent =
  ControllerStateChangeEvent<
    typeof controllerName,
    SeedlessOnboardingControllerState
  >;

// events allowed to be subscribed
export type AllowedEvents =
  | KeyringControllerStateChangeEvent
  | SeedlessOnboardingControllerStateChangeEvent;

// Messenger
// TODO: re-evaluate and remove uncessary events/actions from the messenger
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
   * @description Initial state to set on this controller.
   */
  state?: SeedlessOnboardingControllerState;

  /**
   * @description Encryptor used for encryption and decryption of data.
   * @default WebCryptoAPI
   */
  encryptor?: Encryptor;
};

/**
 * Seedless Onboarding Controller State Metadata.
 *
 * This allows us to choose if fields of the state should be persisted or not
 * using the `persist` flag; and if they can be sent to Sentry or not, using
 * the `anonymous` flag.
 */
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

export const defaultState: SeedlessOnboardingControllerState = {
  hasValidEncryptionKey: false,
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

  readonly toprfAuthClient: ToprfAuthClient;

  constructor({
    messenger,
    encryptor,
    state,
  }: SeedlessOnboardingControllerOptions) {
    super({
      messenger,
      metadata: seedlessOnboardingMetadata,
      name: controllerName,
      state: { ...state, ...defaultState },
    });
    if (encryptor) {
      this.#encryptor = encryptor;
    }
    this.toprfAuthClient = new ToprfAuthClient(this.#encryptor);
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
    const verificationResult = await this.toprfAuthClient.authenticate(params);
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
    const { encKey } = await this.toprfAuthClient.createEncKey({
      nodeAuthTokens,
      password,
    });

    const storeResult = await this.toprfAuthClient.storeSecretData({
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
    try {
      const nodeAuthTokens = this.#getNodeAuthTokens();
      const { encKey, secretData } = await this.toprfAuthClient.fetchSecretData(
        {
          nodeAuthTokens,
          password,
        },
      );

      return {
        secretData,
        encryptionKey: encKey,
      };
    } catch (error) {
      console.error('[fetchAndRestoreSeedPhraseMetadata] error', error);
      throw new Error(SeedlessOnboardingControllerError.IncorrectPassword);
    }
  }

  /**
   * @description Get the node auth tokens from the state.
   * @returns The node auth tokens.
   */
  #getNodeAuthTokens() {
    const { nodeAuthTokens } = this.state;
    if (!nodeAuthTokens) {
      throw new Error(SeedlessOnboardingControllerError.NoOAuthIdToken);
    }
    return nodeAuthTokens;
  }
}

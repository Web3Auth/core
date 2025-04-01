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
import { Mutex, type MutexInterface } from 'async-mutex';

import { SeedlessOnboardingControllerError } from './constants';
import { ToprfAuthClient } from './ToprfClient';
import type {
  AuthenticateUserParams,
  CreateSeedlessBackupParams,
  Encryptor,
  NodeAuthTokens,
} from './types';

const controllerName = 'SeedlessOnboardingController';

/**
 * A function executed within a mutually exclusive lock, with
 * a mutex releaser in its option bag.
 *
 * @param releaseLock - A function to release the lock.
 */
type MutuallyExclusiveCallback<Result> = ({
  releaseLock,
}: {
  releaseLock: MutexInterface.Releaser;
}) => Promise<Result>;

// State
export type SeedlessOnboardingControllerState = {
  /**
   * Encrypted array of serialized keyrings data.
   */
  vault?: string;
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
    vault: {
      persist: true,
      anonymous: false,
    },
    hasValidEncryptionKey: {
      persist: true,
      anonymous: false,
    },
    nodeAuthTokens: {
      persist: false,
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

  readonly #vaultOperationMutex = new Mutex();

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

    await this.#createNewVaultWithAuthData({
      password,
      authTokens: nodeAuthTokens,
      toprfEncryptionKey: storeResult.encKey,
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

      if (secretData && secretData.length > 0) {
        await this.#createNewVaultWithAuthData({
          password,
          authTokens: nodeAuthTokens,
          toprfEncryptionKey: encKey,
        });
      }

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

  async #createNewVaultWithAuthData({
    password,
    authTokens,
    toprfEncryptionKey,
  }: {
    password: string;
    authTokens: NodeAuthTokens;
    toprfEncryptionKey: string;
  }): Promise<void> {
    await this.#updateVault({
      password,
      vaultData: {
        authTokens,
        toprfEncryptionKey,
      },
    });
  }

  #updateVault({
    password,
    vaultData,
  }: {
    password: string;
    vaultData: object;
  }): Promise<boolean> {
    return this.#withVaultLock(async () => {
      if (!password) {
        throw new Error(SeedlessOnboardingControllerError.MissingCredentials);
      }

      const serializedAuthData = await this.#getSerializedVaultData(vaultData);

      const updatedState: Partial<SeedlessOnboardingControllerState> = {};

      assertIsValidPassword(password);
      const key = await this.#encryptor.keyFromPassword(password);
      const result = await this.#encryptor.encryptWithKey(
        key,
        serializedAuthData,
      );
      updatedState.vault = result.data;

      if (!updatedState.vault) {
        throw new Error(SeedlessOnboardingControllerError.MissingVaultData);
      }

      this.update((state) => {
        state.vault = updatedState.vault;
      });

      return true;
    });
  }

  /**
   * Lock the vault mutex before executing the given function,
   * and release it after the function is resolved or after an
   * error is thrown.
   *
   * This ensures that each operation that interacts with the vault
   * is executed in a mutually exclusive way.
   *
   * @param callback - The function to execute while the vault mutex is locked.
   * @returns The result of the function.
   */
  async #withVaultLock<Result>(
    callback: MutuallyExclusiveCallback<Result>,
  ): Promise<Result> {
    return withLock(this.#vaultOperationMutex, callback);
  }

  async #getSerializedVaultData(data: object): Promise<string> {
    return JSON.stringify(data);
  }
}

/**
 * Assert that the provided password is a valid non-empty string.
 *
 * @param password - The password to check.
 * @throws If the password is not a valid string.
 */
function assertIsValidPassword(password: unknown): asserts password is string {
  if (typeof password !== 'string') {
    throw new Error(SeedlessOnboardingControllerError.WrongPasswordType);
  }

  if (!password || !password.length) {
    throw new Error(SeedlessOnboardingControllerError.InvalidEmptyPassword);
  }
}

/**
 * Lock the given mutex before executing the given function,
 * and release it after the function is resolved or after an
 * error is thrown.
 *
 * @param mutex - The mutex to lock.
 * @param callback - The function to execute while the mutex is locked.
 * @returns The result of the function.
 */
async function withLock<Result>(
  mutex: Mutex,
  callback: MutuallyExclusiveCallback<Result>,
): Promise<Result> {
  const releaseLock = await mutex.acquire();

  try {
    return await callback({ releaseLock });
  } finally {
    releaseLock();
  }
}

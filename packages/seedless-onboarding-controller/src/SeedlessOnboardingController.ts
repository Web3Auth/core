import type {
  ControllerGetStateAction,
  ControllerStateChangeEvent,
  RestrictedMessenger,
  StateMetadata,
} from '@metamask/base-controller';
import { BaseController } from '@metamask/base-controller';
import { encrypt, decrypt } from '@metamask/browser-passworder';
import type { KeyringControllerStateChangeEvent } from '@metamask/keyring-controller';
import { Mutex, type MutexInterface } from 'async-mutex';

import { SeedlessOnboardingControllerError } from './constants';
import type { KeyPair } from './ToprfClient';
import { ToprfAuthClient } from './ToprfClient';
import type { Encryptor, NodeAuthTokens, OAuthVerifier } from './types';

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
      anonymous: true,
    },
  };

export const defaultState: SeedlessOnboardingControllerState = {
  hasValidEncryptionKey: false,
};

/**
 * Controller responsible for creating backup and restoring seed phrase for the user.
 */
export class SeedlessOnboardingController extends BaseController<
  typeof controllerName,
  SeedlessOnboardingControllerState,
  SeedlessOnboardingControllerMessenger
> {
  readonly #encryptor: Encryptor = {
    encrypt,
    decrypt,
  };

  readonly #vaultOperationMutex = new Mutex();

  readonly toprfAuthClient: ToprfAuthClient;

  /**
   * Creates a KeyringController instance.
   *
   * @param options - Initial options used to configure this controller
   * @param options.encryptor - An optional object for defining encryption schemes.
   * @param options.messenger - A restricted messenger.
   * @param options.state - Initial state to set on this controller.
   */
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
    this.toprfAuthClient = new ToprfAuthClient();
  }

  /**
   * @description Authenticate OAuth user using the seedless onboarding flow
   * and determine if the user is already registered or not.
   * @param params - The parameters for authenticate OAuth user.
   * @param params.idTokens - The ID tokens from Social login
   * @param params.verifier - OAuth verifier
   * @param params.verifierID - user email or id from Social login
   * @param params.indexes - The indexes of the nodes to use for authentication
   * @param params.endpoints - The endpoints to verify the idTokens
   * @returns A promise that resolves to the authentication result.
   */
  async authenticateOAuthUser(params: {
    verifier: OAuthVerifier;
    verifierID: string;
    idTokens: string[];
    indexes: number[];
    endpoints: string[];
  }) {
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
   * @param params.verifier - The login provider of the user.
   * @param params.verifierID - The deterministic identifier of the user from the login provider.
   * @param params.password - The password used to create new wallet and seedphrase
   * @param params.seedPhrase - The seed phrase to backup
   * @returns A promise that resolves to the encrypted seed phrase and the encryption key.
   */
  async createSeedPhraseBackup(params: {
    verifier: OAuthVerifier;
    verifierID: string;
    seedPhrase: Uint8Array;
    password: string;
  }): Promise<void> {
    const { verifier, verifierID, password, seedPhrase } = params;
    const nodeAuthTokens = this.#getNodeAuthTokens();
    const { encKey, authKeyPair } = await this.toprfAuthClient.createEncKey({
      nodeAuthTokens,
      password,
      verifier,
      verifierID,
    });

    await this.toprfAuthClient.addSecretDataItem({
      nodeAuthTokens,
      encKey,
      secretData: seedPhrase,
      authKeyPair,
    });

    await this.#createNewVaultWithAuthData({
      password,
      authTokens: nodeAuthTokens,
      rawToprfEncryptionKey: encKey,
      rawToprfAuthKeyPair: authKeyPair,
    });
  }

  /**
   * @description Fetch seed phrase metadata from the metadata store.
   * @param verifier - The login provider of the user.
   * @param verifierID - The deterministic identifier of the user from the login provider.
   * @param password - The password used to create new wallet and seedphrase
   * @returns A promise that resolves to the seed phrase metadata.
   */
  async fetchAndRestoreSeedPhraseMetadata(
    verifier: OAuthVerifier,
    verifierID: string,
    password: string,
  ): Promise<Uint8Array[]> {
    const nodeAuthTokens = this.#getNodeAuthTokens();
    const { encKey, authKeyPair } = await this.toprfAuthClient.createEncKey({
      nodeAuthTokens,
      password,
      verifier,
      verifierID,
    });
    const secretData = await this.toprfAuthClient.fetchAllSecretData({
      nodeAuthTokens,
      decKey: encKey,
      authKeyPair,
    });

    if (secretData && secretData.length > 0) {
      await this.#createNewVaultWithAuthData({
        password,
        authTokens: nodeAuthTokens,
        rawToprfEncryptionKey: encKey,
        rawToprfAuthKeyPair: authKeyPair,
      });
    }

    return secretData;
  }

  /**
   * @description Update the password of the seedless onboarding flow.
   *
   * Changing password will also update the encryption key and metadata store with new encrypted values.
   *
   * @param params - The parameters for updating the password.
   * @param params.verifierID - The deterministic identifier of the user from the login provider.
   * @param params.verifier - The login provider of the user.
   * @param params.newPassword - The new password to update.
   * @param params.oldPassword - The old password to verify.
   */
  async updatePassword(params: {
    verifier: OAuthVerifier;
    verifierID: string;
    newPassword: string;
    oldPassword: string;
  }) {
    const { verifier, verifierID, newPassword, oldPassword } = params;

    // 1. unlock the encrypted vault with old password, retrieve the ek and authTokens from the vault
    const { nodeAuthTokens, toprfEncryptionKey, toprfAuthKeyPair } =
      await this.#unlockVault(oldPassword);
    // 2. call changePassword method from Toprf Client with old password, new password
    const { encKey: newEncKey, authKeyPair: newAuthKeyPair } =
      await this.toprfAuthClient.changeEncKey({
        nodeAuthTokens,
        verifier,
        verifierID,
        oldEncKey: toprfEncryptionKey,
        oldAuthKeyPair: toprfAuthKeyPair,
        password: newPassword,
      });

    // 3. update and encrypt the vault with new password
    await this.#createNewVaultWithAuthData({
      password: newPassword,
      authTokens: nodeAuthTokens,
      rawToprfEncryptionKey: newEncKey,
      rawToprfAuthKeyPair: newAuthKeyPair,
    });
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

  async #unlockVault(password: string): Promise<{
    nodeAuthTokens: NodeAuthTokens;
    toprfEncryptionKey: Uint8Array;
    toprfAuthKeyPair: KeyPair;
  }> {
    return this.#withVaultLock(async () => {
      assertIsValidPassword(password);

      const encryptedVault = this.state.vault;
      if (!encryptedVault) {
        throw new Error(SeedlessOnboardingControllerError.VaultError);
      }

      const decryptedVaultData = await this.#encryptor.decrypt(
        password,
        encryptedVault,
      );

      return this.#parseVaultData(decryptedVaultData);
    });
  }

  /**
   * Create a new vault with the given password and auth data from the Toprf Client.
   *
   * @param params - The parameters for creating a new vault.
   * @param params.password - The password to encrypt the vault.
   * @param params.authTokens - The auth tokens to store in the vault.
   * @param params.rawToprfEncryptionKey - The raw encryption key to encrypt/decrypt the Encrypted Seed Phrase.
   * @param params.rawToprfAuthKeyPair - The raw authentication key pair to authenticate the user for storing the Encrypted Seed Phrase.
   */
  async #createNewVaultWithAuthData({
    password,
    authTokens,
    rawToprfEncryptionKey,
    rawToprfAuthKeyPair,
  }: {
    password: string;
    authTokens: NodeAuthTokens;
    rawToprfEncryptionKey: Uint8Array;
    rawToprfAuthKeyPair: KeyPair;
  }): Promise<void> {
    const { toprfEncryptionKey, toprfAuthKeyPair } =
      await this.#serializeKeyData(rawToprfEncryptionKey, rawToprfAuthKeyPair);

    await this.#updateVault({
      password,
      vaultData: {
        authTokens,
        toprfEncryptionKey,
        toprfAuthKeyPair,
      },
    });
  }

  /**
   * Encrypt the vault with the given password and update vault data.
   *
   * @param params - The parameters for updating the vault.
   * @param params.password - The password to update the vault.
   * @param params.vaultData - The vault data to update.
   * @returns A promise that resolves to the boolean value.
   */
  async #updateVault({
    password,
    vaultData,
  }: {
    password: string;
    vaultData: object;
  }): Promise<boolean> {
    return this.#withVaultLock(async () => {
      assertIsValidPassword(password);

      const serializedStateData = await this.#getSerializedStateData(vaultData);

      const updatedState: Partial<SeedlessOnboardingControllerState> = {};

      updatedState.vault = await this.#encryptor.encrypt(
        password,
        serializedStateData,
      );

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

  /**
   * Serialize the data to the JSON string.
   *
   * @param data - The state data to serialize.
   * @returns The serialized state data.
   */
  async #getSerializedStateData(data: object): Promise<string> {
    return JSON.stringify(data);
  }

  /**
   * @description Serialize the encryption key and authentication key pair.
   * @param encKey - The encryption key to serialize.
   * @param authKeyPair - The authentication key pair to serialize.
   * @returns The serialized encryption key and authentication key pair.
   */
  async #serializeKeyData(
    encKey: Uint8Array,
    authKeyPair: KeyPair,
  ): Promise<{
    toprfEncryptionKey: string;
    toprfAuthKeyPair: string;
  }> {
    const b64EncodedEncKey = Buffer.from(encKey).toString('base64');
    const b64EncodedAuthKeyPair = JSON.stringify({
      sk: authKeyPair.sk.toString(),
      pk: Buffer.from(authKeyPair.pk).toString('base64'),
    });

    return {
      toprfEncryptionKey: b64EncodedEncKey,
      toprfAuthKeyPair: b64EncodedAuthKeyPair,
    };
  }

  /**
   * Parse the vault data from the serialized string
   *
   * @param data - The vault data to parse.
   * @returns The parsed vault data.
   */
  async #parseVaultData(data: unknown): Promise<{
    nodeAuthTokens: NodeAuthTokens;
    toprfEncryptionKey: Uint8Array;
    toprfAuthKeyPair: KeyPair;
  }> {
    if (typeof data !== 'string') {
      throw new Error(SeedlessOnboardingControllerError.VaultDataError);
    }

    const parsedVaultData = JSON.parse(data);

    if (
      !('authTokens' in parsedVaultData) ||
      !('toprfEncryptionKey' in parsedVaultData) ||
      !('toprfAuthKeyPair' in parsedVaultData)
    ) {
      throw new Error(SeedlessOnboardingControllerError.VaultDataError);
    }

    const rawToprfEncryptionKey = new Uint8Array(
      Buffer.from(parsedVaultData.toprfEncryptionKey, 'base64'),
    );
    const parsedToprfAuthKeyPair = JSON.parse(parsedVaultData.toprfAuthKeyPair);
    const rawToprfAuthKeyPair = {
      sk: BigInt(parsedToprfAuthKeyPair.sk),
      pk: new Uint8Array(Buffer.from(parsedToprfAuthKeyPair.pk, 'base64')),
    };

    return {
      nodeAuthTokens: parsedVaultData.authTokens,
      toprfEncryptionKey: rawToprfEncryptionKey,
      toprfAuthKeyPair: rawToprfAuthKeyPair,
    };
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

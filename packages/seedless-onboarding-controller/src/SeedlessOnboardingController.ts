import type {
  ControllerGetStateAction,
  ControllerStateChangeEvent,
  RestrictedMessenger,
  StateMetadata,
} from '@metamask/base-controller';
import { BaseController } from '@metamask/base-controller';
import { encrypt, decrypt } from '@metamask/browser-passworder';
import type { KeyringControllerStateChangeEvent } from '@metamask/keyring-controller';
import type {
  AuthenticateParams,
  KeyPair,
  NodeAuthTokens,
  SEC1EncodedPublicKey,
} from '@metamask/toprf-secure-backup';
import { ToprfSecureBackup } from '@metamask/toprf-secure-backup';
import { utf8ToBytes } from '@noble/ciphers/utils';
import { Mutex, type MutexInterface } from 'async-mutex';
import log from 'loglevel';

import { SeedlessOnboardingControllerError } from './constants';
import type { Encryptor, OAuthVerifier, UpdatePasswordParams } from './types';

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
   * If this value is `false`, we can assume that user already has completed the `SeedPhrase` generation step, and user will have to
   * fetch the `SeedPhrase` with correct password. Otherwise, users will be asked to set up seedphrase and password, first.
   */
  isNewUser?: boolean;
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

  network?: 'sapphire_mainnet' | 'sapphire_devnet';

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
    isNewUser: {
      persist: true,
      anonymous: false,
    },
    nodeAuthTokens: {
      persist: false,
      anonymous: true,
    },
  };

export const defaultState: SeedlessOnboardingControllerState = {
  isNewUser: true,
};

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

  readonly toprfClient: ToprfSecureBackup;

  constructor({
    messenger,
    encryptor,
    state,
    network,
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

    this.toprfClient = new ToprfSecureBackup({
      network: network || 'sapphire_devnet',
    });
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
  async authenticate(params: AuthenticateParams) {
    try {
      const authenticationResult = await this.toprfClient.authenticate(params);
      this.update((state) => {
        state.nodeAuthTokens = authenticationResult.nodeAuthTokens;
        state.isNewUser = authenticationResult.isNewUser;
      });
      return authenticationResult;
    } catch (error) {
      log.error('Error authenticating user', error);
      throw new Error(SeedlessOnboardingControllerError.AuthenticationError);
    }
  }

  /**
   * @description Backup seed phrase using the seedless onboarding flow.
   * @param params - The parameters for backup seed phrase.
   * @param params.verifier - The login provider of the user.
   * @param params.verifierId - The deterministic identifier of the user from the login provider.
   * @param params.password - The password used to create new wallet and seedphrase
   * @param params.seedPhrase - The seed phrase to backup
   * @returns A promise that resolves to the encrypted seed phrase and the encryption key.
   */
  async createSeedPhraseBackup({
    verifier,
    verifierId,
    password,
    seedPhrase,
  }: {
    verifier: OAuthVerifier;
    verifierId: string;
    password: string;
    seedPhrase: Uint8Array;
  }): Promise<void> {
    this.#assertIsValidNodeAuthTokens();

    // locally evaluate the encryption key from the password
    const { encKey, authKeyPair, oprfKey } = this.toprfClient.createLocalEncKey(
      {
        password,
      },
    );

    // encrypt and store the seed phrase backup
    await this.#encryptAndStoreSeedPhraseBackup(
      seedPhrase,
      encKey,
      authKeyPair,
    );

    // store/presist the encryption key shares
    await this.#persistLocalEncKey({
      verifier,
      verifierId,
      oprfKey,
      authPubKey: authKeyPair.pk,
    });

    // create a new vault with the resulting authentication data
    await this.#createNewVaultWithAuthData({
      password,
      rawToprfEncryptionKey: encKey,
      rawToprfAuthKeyPair: authKeyPair,
    });
  }

  /**
   * @description Fetch seed phrase metadata from the metadata store.
   * @param verifier - The login provider of the user.
   * @param verifierId - The deterministic identifier of the user from the login provider.
   * @param password - The password used to create new wallet and seedphrase
   * @returns A promise that resolves to the seed phrase metadata.
   */
  async fetchAndRestoreSeedPhrase(
    verifier: OAuthVerifier,
    verifierId: string,
    password: string,
  ): Promise<Uint8Array[]> {
    this.#assertIsValidNodeAuthTokens();

    const { encKey, authKeyPair } = await this.#recoveryEncKey(
      verifier,
      verifierId,
      password,
    );

    const secretData = await this.toprfClient.fetchAllSecretDataItems({
      decKey: encKey,
      authKeyPair,
    });

    if (secretData && secretData.length > 0) {
      await this.#createNewVaultWithAuthData({
        password,
        rawToprfEncryptionKey: encKey,
        rawToprfAuthKeyPair: authKeyPair,
      });
    }

    return this.#parseSeedPhraseFromMetadataStore(secretData);
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
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  async updatePassword(params: UpdatePasswordParams) {
    // TODO: implement this once we have the `changePassword` method in Toprf Client
    // const { verifier, verifierID, newPassword, oldPassword } = params;
    // // 1. unlock the encrypted vault with old password, retrieve the ek and authTokens from the vault
    // const { nodeAuthTokens, toprfEncryptionKey, toprfAuthKeyPair } =
    //   await this.#unlockVault(oldPassword);
    // // 2. call changePassword method from Toprf Client with old password, new password
    // // 3. update and encrypt the vault with new password
    // await this.#createNewVaultWithAuthData({
    //   password: newPassword,
    //   authTokens: nodeAuthTokens,
    //   rawToprfEncryptionKey: newEncKey,
    //   rawToprfAuthKeyPair: newAuthKeyPair,
    // });
  }

  /**
   * Persist the encryption key for the seedless onboarding flow.
   *
   * @param params - The parameters for persisting the encryption key.
   * @param params.verifier - The login provider of the user.
   * @param params.verifierId - The deterministic identifier of the user from the login provider.
   * @param params.oprfKey - The OPRF key to be splited and persisted.
   * @param params.authPubKey - The authentication public key.
   * @returns A promise that resolves to the encryption key.
   */
  async #persistLocalEncKey({
    verifier,
    verifierId,
    oprfKey,
    authPubKey,
  }: {
    verifier: OAuthVerifier;
    verifierId: string;
    oprfKey: bigint;
    authPubKey: SEC1EncodedPublicKey;
  }) {
    const nodeAuthTokens = this.#getNodeAuthTokens();
    try {
      await this.toprfClient.persistLocalEncKey({
        nodeAuthTokens,
        verifier,
        verifierId,
        oprfKey,
        authPubKey,
      });
    } catch (error) {
      log.error('Error persisting local encryption key', error);
      throw new Error(SeedlessOnboardingControllerError.AuthenticationError);
    }
  }

  /**
   * @description Recover the encryption key from password.
   * @param verifier - The login provider of the user.
   * @param verifierId - The deterministic identifier of the user from the login provider.
   * @param password - The password used to derive the encryption key.
   * @returns A promise that resolves to the encryption key.
   */
  async #recoveryEncKey(
    verifier: OAuthVerifier,
    verifierId: string,
    password: string,
  ) {
    const nodeAuthTokens = this.#getNodeAuthTokens();

    try {
      const recoverEncKeyResult = await this.toprfClient.recoverEncKey({
        nodeAuthTokens,
        password,
        verifier,
        verifierId,
      });
      return recoverEncKeyResult;
    } catch (error) {
      log.error('Error recovering encryption key', error);
      throw new Error(SeedlessOnboardingControllerError.AuthenticationError);
    }
  }

  /**
   * Encrypt and store the seed phrase backup in the metadata store.
   *
   * @param seedPhrase - The seed phrase to store.
   * @param encKey - The encryption key to store.
   * @param authKeyPair - The authentication key pair to store.
   */
  async #encryptAndStoreSeedPhraseBackup(
    seedPhrase: Uint8Array,
    encKey: Uint8Array,
    authKeyPair: KeyPair,
  ) {
    const seedPhraseMetadata = this.#parseSeedPhraseMetadata(seedPhrase);
    await this.toprfClient.addSecretDataItem({
      encKey,
      secretData: seedPhraseMetadata,
      authKeyPair,
    });
  }

  /**
   * @description Get the node auth tokens from the state.
   * @returns The node auth tokens.
   */
  #getNodeAuthTokens() {
    const { nodeAuthTokens } = this.state;
    if (!nodeAuthTokens || nodeAuthTokens.length === 0) {
      throw new Error(SeedlessOnboardingControllerError.NoOAuthIdToken);
    }
    return nodeAuthTokens;
  }

  // eslint-disable-next-line no-unused-private-class-members
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

  async #createNewVaultWithAuthData({
    password,
    rawToprfEncryptionKey,
    rawToprfAuthKeyPair,
  }: {
    password: string;
    rawToprfEncryptionKey: Uint8Array;
    rawToprfAuthKeyPair: KeyPair;
  }): Promise<void> {
    const { toprfEncryptionKey, toprfAuthKeyPair } =
      await this.#serializeKeyData(rawToprfEncryptionKey, rawToprfAuthKeyPair);

    const authTokens = this.#getNodeAuthTokens();

    await this.#updateVault({
      password,
      vaultData: {
        authTokens,
        toprfEncryptionKey,
        toprfAuthKeyPair,
      },
    });
  }

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
      sk: `0x${authKeyPair.sk.toString(16)}`, // Convert BigInt to hex string
      pk: Buffer.from(authKeyPair.pk).toString('base64'),
    });

    return {
      toprfEncryptionKey: b64EncodedEncKey,
      toprfAuthKeyPair: b64EncodedAuthKeyPair,
    };
  }

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

  /**
   * Parse the seed phrase metadata to be stored in the metadata store.
   *
   * Along with the seed phrase, we also store the timestamp when the seed phrase was backed up.
   * This helps us preserve the seedphrase order when the user restores the multiple seedphrase from the metadata store.
   *
   * @param seedPhrase - The seed phrase to parse.
   * @returns The parsed seed phrase metadata.
   */
  #parseSeedPhraseMetadata(seedPhrase: Uint8Array): Uint8Array {
    const b64SeedPhrase = Buffer.from(seedPhrase).toString('base64');
    const seedPhraseMetadata = JSON.stringify({
      seedPhrase: b64SeedPhrase,
      timestamp: Date.now(),
    });

    return utf8ToBytes(seedPhraseMetadata);
  }

  /**
   * Parse the seed phrase metadata from the metadata store.
   *
   * @param seedPhraseMetadataArr - The array of SeedPhrase Metadata from the metadata store.
   * @returns The parsed seed phrase metadata.
   */
  #parseSeedPhraseFromMetadataStore(
    seedPhraseMetadataArr: Uint8Array[],
  ): Uint8Array[] {
    const seedPhrases = seedPhraseMetadataArr.map((metadata) => {
      const serializedMetadata = Buffer.from(metadata).toString('utf-8');
      const parsedMetadata = JSON.parse(serializedMetadata);

      if ('seedPhrase' in parsedMetadata || 'timestamp' in parsedMetadata) {
        return {
          seedPhrase: new Uint8Array(
            Buffer.from(parsedMetadata.seedPhrase, 'base64'),
          ),
          timestamp: parsedMetadata.timestamp,
        };
      }

      throw new Error(
        SeedlessOnboardingControllerError.InvalidSeedPhraseMetadata,
      );
    });

    // sort by the timestamp
    seedPhrases.sort((a, b) => a.timestamp - b.timestamp);

    return seedPhrases.map((phrase) => phrase.seedPhrase);
  }

  /**
   * Assert that the node auth tokens are present in the state.
   *
   * @throws If the node auth tokens are not present in the state.
   */
  #assertIsValidNodeAuthTokens() {
    const { nodeAuthTokens } = this.state;
    if (!nodeAuthTokens || nodeAuthTokens.length === 0) {
      throw new Error(SeedlessOnboardingControllerError.NoOAuthIdToken);
    }
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

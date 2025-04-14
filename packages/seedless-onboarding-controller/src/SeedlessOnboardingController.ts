import type { StateMetadata } from '@metamask/base-controller';
import { BaseController } from '@metamask/base-controller';
import { encrypt, decrypt } from '@metamask/browser-passworder';
import type {
  KeyPair,
  NodeAuthTokens,
  SEC1EncodedPublicKey,
} from '@metamask/toprf-secure-backup';
import { ToprfSecureBackup } from '@metamask/toprf-secure-backup';
import { keccak_256 as keccak256 } from '@noble/hashes/sha3';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils';
import { Mutex } from 'async-mutex';
import log from 'loglevel';

import { controllerName, SeedlessOnboardingControllerError } from './constants';
import { SeedphraseMetadata } from './SeedphraseMetadata';
import type {
  Encryptor,
  MutuallyExclusiveCallback,
  SeedlessOnboardingControllerMessenger,
  SeedlessOnboardingControllerOptions,
  SeedlessOnboardingControllerState,
  VaultData,
} from './types';

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
   * @param params.idTokens - The ID token from Social login
   * @param params.authConnectionId - OAuth authConnectionId from dashboard
   * @param params.userId - user email or id from Social login
   * @param params.groupedAuthConnectionId - Optional grouped authConnectionId to be used for the authenticate request.
   * You can pass this to use aggregate connection.
   * @returns A promise that resolves to the authentication result.
   */
  async authenticate(params: {
    idTokens: string[];
    authConnectionId: string;
    groupedAuthConnectionId?: string;
    userId: string;
  }) {
    try {
      const { idTokens, authConnectionId, groupedAuthConnectionId, userId } =
        params;
      const verifier = groupedAuthConnectionId || authConnectionId;
      const verifierId = userId;
      const hashedIdTokens = idTokens.map((idToken) => {
        return bytesToHex(keccak256(utf8ToBytes(idToken)));
      });
      const authenticationResult = await this.toprfClient.authenticate({
        verifier,
        verifierId,
        idTokens: hashedIdTokens,
        singleIdVerifierParams: {
          subVerifier: authConnectionId,
          subVerifierIdTokens: idTokens,
        },
      });
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
   * @param params.authConnectionId - OAuth authConnectionId from dashboard
   * @param params.groupedAuthConnectionId - Optional grouped authConnectionId to be used for the authenticate request.
   * You can pass this to use aggregate connection.
   * @param params.userId - user email or id from Social login
   * @param params.password - The password used to create new wallet and seedphrase
   * @param params.seedPhrase - The seed phrase to backup
   * @returns A promise that resolves to the encrypted seed phrase and the encryption key.
   */
  async createSeedPhraseBackup({
    authConnectionId,
    groupedAuthConnectionId,
    userId,
    password,
    seedPhrase,
  }: {
    authConnectionId: string;
    groupedAuthConnectionId?: string;
    userId: string;
    password: string;
    seedPhrase: Uint8Array;
  }): Promise<void> {
    this.#assertIsValidNodeAuthTokens(this.state.nodeAuthTokens);

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
    await this.#persistOprfKey({
      groupedAuthConnectionId,
      authConnectionId,
      userId,
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
   * @param params - The parameters for fetching seed phrase metadata.
   * @param params.authConnectionId - OAuth authConnectionId from dashboard
   * @param params.groupedAuthConnectionId - Optional grouped authConnectionId to be used for the authenticate request.
   * You can pass this to use aggregate connection.
   * @param params.userId - user email or id from Social login
   * @param params.password - The password used to create new wallet and seedphrase
   * @returns A promise that resolves to the seed phrase metadata.
   */
  async fetchAndRestoreSeedPhrase(params: {
    authConnectionId: string;
    groupedAuthConnectionId?: string;
    userId: string;
    password: string;
  }): Promise<Uint8Array[]> {
    const { authConnectionId, groupedAuthConnectionId, userId, password } =
      params;
    this.#assertIsValidNodeAuthTokens(this.state.nodeAuthTokens);

    const { encKey, authKeyPair } = await this.#recoverEncKey({
      authConnectionId,
      groupedAuthConnectionId,
      userId,
      password,
    });

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
   * @param params.authConnectionId - OAuth authConnectionId from dashboard
   * @param params.groupedAuthConnectionId - Optional grouped authConnectionId to be used for the authenticate request.
   * You can pass this to use aggregate connection.
   * @param params.userId - user email or id from Social login
   * @param params.newPassword - The new password to update.
   * @param params.oldPassword - The old password to verify.
   */
  async changePassword(params: {
    authConnectionId: string;
    groupedAuthConnectionId?: string;
    userId: string;
    newPassword: string;
    oldPassword: string;
  }) {
    this.#assertIsValidNodeAuthTokens(this.state.nodeAuthTokens);

    // verify the old password of the encrypted vault
    await this.#verifyPassword(params.oldPassword);

    // update the encryption key with new password and update the Metadata Store
    const { encKey: newEncKey, authKeyPair: newAuthKeyPair } =
      await this.#changeEncryptionKey(params);

    // update and encrypt the vault with new password
    await this.#createNewVaultWithAuthData({
      password: params.newPassword,
      rawToprfEncryptionKey: newEncKey,
      rawToprfAuthKeyPair: newAuthKeyPair,
    });
  }

  /**
   * Update the encryption key with new password and update the Metadata Store with new encryption key.
   *
   * @param params - The parameters for updating the encryption key.
   * @param params.authConnectionId - OAuth authConnectionId from dashboard
   * @param params.groupedAuthConnectionId - Optional grouped authConnectionId to be used for the authenticate request.
   * You can pass this to use aggregate connection.
   * @param params.userId - user email or id from Social login
   * @param params.newPassword - The new password to update.
   * @param params.oldPassword - The old password to verify.
   * @returns A promise that resolves to new encryption key and authentication key pair.
   */
  async #changeEncryptionKey(params: {
    authConnectionId: string;
    groupedAuthConnectionId?: string;
    userId: string;
    newPassword: string;
    oldPassword: string;
  }) {
    const {
      authConnectionId,
      groupedAuthConnectionId,
      userId,
      newPassword,
      oldPassword,
    } = params;

    const { nodeAuthTokens } = this.state;
    this.#assertIsValidNodeAuthTokens(nodeAuthTokens);

    const {
      encKey,
      authKeyPair,
      shareKeyIndex: newShareKeyIndex,
    } = await this.#recoverEncKey({
      authConnectionId,
      groupedAuthConnectionId,
      userId,
      password: oldPassword,
    });

    return await this.toprfClient.changeEncKey({
      nodeAuthTokens,
      verifier: groupedAuthConnectionId || authConnectionId,
      verifierId: userId,
      oldEncKey: encKey,
      oldAuthKeyPair: authKeyPair,
      newShareKeyIndex,
      newPassword,
    });
  }

  /**
   * Persist the encryption key for the seedless onboarding flow.
   *
   * @param params - The parameters for persisting the encryption key.
   * @param params.authConnectionId - OAuth authConnectionId from dashboard
   * @param params.groupedAuthConnectionId - Optional grouped authConnectionId to be used for the authenticate request.
   * You can pass this to use aggregate connection.
   * @param params.userId - user email or id from Social login
   * @param params.oprfKey - The OPRF key to be splited and persisted.
   * @param params.authPubKey - The authentication public key.
   * @returns A promise that resolves to the success of the operation.
   */
  async #persistOprfKey(params: {
    authConnectionId: string;
    groupedAuthConnectionId?: string;
    userId: string;
    oprfKey: bigint;
    authPubKey: SEC1EncodedPublicKey;
  }) {
    const { nodeAuthTokens } = this.state;
    this.#assertIsValidNodeAuthTokens(nodeAuthTokens);

    try {
      await this.toprfClient.persistOprfKey({
        nodeAuthTokens,
        verifier: params.groupedAuthConnectionId || params.authConnectionId,
        verifierId: params.userId,
        oprfKey: params.oprfKey,
        authPubKey: params.authPubKey,
      });
    } catch (error) {
      log.error('Error persisting local encryption key', error);
      throw new Error(SeedlessOnboardingControllerError.AuthenticationError);
    }
  }

  /**
   * @description Recover the encryption key from password.
   * @param params - The parameters for recovering the encryption key.
   * @param params.authConnectionId - OAuth authConnectionId from dashboard
   * @param params.groupedAuthConnectionId - Optional grouped authConnectionId to be used for the authenticate request.
   * You can pass this to use aggregate connection.
   * @param params.userId - user email or id from Social login
   * @param params.password - The password used to derive the encryption key.
   * @returns A promise that resolves to the encryption key and authentication key pair.
   */
  async #recoverEncKey(params: {
    authConnectionId: string;
    groupedAuthConnectionId?: string;
    userId: string;
    password: string;
  }) {
    const { nodeAuthTokens } = this.state;
    this.#assertIsValidNodeAuthTokens(nodeAuthTokens);

    try {
      const recoverEncKeyResult = await this.toprfClient.recoverEncKey({
        nodeAuthTokens,
        password: params.password,
        verifier: params.groupedAuthConnectionId || params.authConnectionId,
        verifierId: params.userId,
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
    const seedPhraseMetadata = new SeedphraseMetadata(seedPhrase);
    const secretData = seedPhraseMetadata.toBytes();
    await this.toprfClient.addSecretDataItem({
      encKey,
      secretData,
      authKeyPair,
    });
  }

  /**
   * Verify the password of the encrypted vault.
   *
   * @param password - The password to verify.
   * @returns A promise that resolves to the decrypted vault data.
   */
  async #verifyPassword(password: string): Promise<{
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
   * Create a new vault with the given authentication data.
   *
   * Serialize the authentication and key data which will be stored in the vault.
   *
   * @param params - The parameters for creating a new vault.
   * @param params.password - The password to encrypt the vault.
   * @param params.rawToprfEncryptionKey - The encryption key to encrypt the vault.
   * @param params.rawToprfAuthKeyPair - The authentication key pair to encrypt the vault.
   */
  async #createNewVaultWithAuthData({
    password,
    rawToprfEncryptionKey,
    rawToprfAuthKeyPair,
  }: {
    password: string;
    rawToprfEncryptionKey: Uint8Array;
    rawToprfAuthKeyPair: KeyPair;
  }): Promise<void> {
    const { nodeAuthTokens } = this.state;
    this.#assertIsValidNodeAuthTokens(nodeAuthTokens);

    const { toprfEncryptionKey, toprfAuthKeyPair } =
      await this.#serializeKeyData(rawToprfEncryptionKey, rawToprfAuthKeyPair);

    const serializedVaultData = JSON.stringify({
      authTokens: nodeAuthTokens,
      toprfEncryptionKey,
      toprfAuthKeyPair,
    });

    await this.#updateVault({
      password,
      serializedVaultData,
    });
  }

  /**
   * Encrypt and update the vault with the given authentication data.
   *
   * @param params - The parameters for updating the vault.
   * @param params.password - The password to encrypt the vault.
   * @param params.serializedVaultData - The serialized authentication data to update the vault with.
   * @returns A promise that resolves to the updated vault.
   */
  async #updateVault({
    password,
    serializedVaultData,
  }: {
    password: string;
    serializedVaultData: string;
  }): Promise<boolean> {
    return this.#withVaultLock(async () => {
      assertIsValidPassword(password);

      const updatedState: Partial<SeedlessOnboardingControllerState> = {};

      updatedState.vault = await this.#encryptor.encrypt(
        password,
        serializedVaultData,
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

  /**
   * Parse and deserialize the authentication data from the vault.
   *
   * @param data - The decrypted vault data.
   * @returns The parsed authentication data.
   * @throws If the vault data is not valid.
   */
  async #parseVaultData(data: unknown): Promise<{
    nodeAuthTokens: NodeAuthTokens;
    toprfEncryptionKey: Uint8Array;
    toprfAuthKeyPair: KeyPair;
  }> {
    if (typeof data !== 'string') {
      throw new Error(SeedlessOnboardingControllerError.InvalidVaultData);
    }

    let parsedVaultData: unknown;
    try {
      parsedVaultData = JSON.parse(data);
    } catch {
      throw new Error(SeedlessOnboardingControllerError.InvalidVaultData);
    }

    this.#assertIsValidVaultData(parsedVaultData);

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
   * Parse the seed phrase metadata from the metadata store.
   *
   * @param seedPhraseMetadataArr - The array of SeedPhrase Metadata from the metadata store.
   * @returns The parsed seed phrase metadata.
   */
  #parseSeedPhraseFromMetadataStore(
    seedPhraseMetadataArr: Uint8Array[],
  ): Uint8Array[] {
    const parsedSeedPhraseMetadata = seedPhraseMetadataArr.map((metadata) =>
      SeedphraseMetadata.fromRawMetadata(metadata),
    );

    const seedPhrases = SeedphraseMetadata.sort(parsedSeedPhraseMetadata);

    return seedPhrases.map(
      (seedPhraseMetadata) => seedPhraseMetadata.seedPhrase,
    );
  }

  /**
   * Check if the provided value is a valid node auth tokens.
   *
   * @param value - The value to check.
   * @throws If the value is not a valid node auth tokens.
   */
  #assertIsValidNodeAuthTokens(
    value: unknown,
  ): asserts value is NodeAuthTokens {
    if (!Array.isArray(value) || value.length === 0) {
      throw new Error(SeedlessOnboardingControllerError.NoOAuthIdToken);
    }
  }

  /**
   * Check if the provided value is a valid vault data.
   *
   * @param value - The value to check.
   * @throws If the value is not a valid vault data.
   */
  #assertIsValidVaultData(value: unknown): asserts value is VaultData {
    // value is not valid vault data if any of the following conditions are true:
    if (
      !value || // value is not defined
      typeof value !== 'object' || // value is not an object
      !('authTokens' in value) || // authTokens is not defined
      typeof value.authTokens !== 'object' || // authTokens is not an object
      !('toprfEncryptionKey' in value) || // toprfEncryptionKey is not defined
      typeof value.toprfEncryptionKey !== 'string' || // toprfEncryptionKey is not a string
      !('toprfAuthKeyPair' in value) || // toprfAuthKeyPair is not defined
      typeof value.toprfAuthKeyPair !== 'string' // toprfAuthKeyPair is not a string
    ) {
      throw new Error(SeedlessOnboardingControllerError.VaultDataError);
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

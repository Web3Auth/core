import type {
  ChangeEncryptionKeyResult,
  KeyPair,
  NodeAuthTokens,
  RecoverEncryptionKeyResult,
  ToprfSecureBackup,
} from '@metamask/toprf-secure-backup';

import { SeedlessOnboardingControllerError } from './constants';
import { SeedlessOnboardingController } from './SeedlessOnboardingController';
import type {
  SeedlessOnboardingControllerMessenger,
  SeedlessOnboardingControllerOptions,
  SeedlessOnboardingControllerState,
} from './types';
import {
  handleMockSecretDataGet,
  handleMockSecretDataAdd,
  handleMockCommitment,
  handleMockAuthenticate,
} from '../tests/__fixtures__/topfClient';
import {
  createMockSecretDataGetResponse,
  MULTIPLE_MOCK_SEEDPHRASE_METADATA,
} from '../tests/mocks/toprf';
import { MockToprfEncryptorDecryptor } from '../tests/mocks/toprfEncryptor';
import MockVaultEncryptor from '../tests/mocks/vaultEncryptor';

type WithControllerCallback<ReturnValue> = ({
  controller,
  initialState,
  encryptor,
  messenger,
}: {
  controller: SeedlessOnboardingController;
  encryptor: MockVaultEncryptor;
  initialState: SeedlessOnboardingControllerState;
  messenger: SeedlessOnboardingControllerMessenger;
  toprfClient: ToprfSecureBackup;
}) => Promise<ReturnValue> | ReturnValue;

type WithControllerOptions = Partial<SeedlessOnboardingControllerOptions>;

type WithControllerArgs<ReturnValue> =
  | [WithControllerCallback<ReturnValue>]
  | [WithControllerOptions, WithControllerCallback<ReturnValue>];

/**
 * Creates a mock user operation messenger.
 *
 * @returns The mock user operation messenger.
 */
function buildSeedlessOnboardingControllerMessenger() {
  return {
    call: jest.fn(),
    publish: jest.fn(),
    registerActionHandler: jest.fn(),
    registerInitialEventPayload: jest.fn(),
    subscribe: jest.fn(),
  } as unknown as jest.Mocked<SeedlessOnboardingControllerMessenger>;
}

/**
 * Builds a mock encryptor for the vault.
 *
 * @returns The mock encryptor.
 */
function createMockVaultEncryptor() {
  return new MockVaultEncryptor();
}

/**
 * Builds a controller based on the given options and creates a new vault
 * and keychain, then calls the given function with that controller.
 *
 * @param args - Either a function, or an options bag + a function. The options
 * bag is equivalent to the options that KeyringController takes;
 * the function will be called with the built controller, along with its
 * preferences, encryptor and initial state.
 * @returns Whatever the callback returns.
 */
async function withController<ReturnValue>(
  ...args: WithControllerArgs<ReturnValue>
) {
  const [{ ...rest }, fn] = args.length === 2 ? args : [{}, args[0]];
  const encryptor = new MockVaultEncryptor();
  const messenger = buildSeedlessOnboardingControllerMessenger();

  const initialState: SeedlessOnboardingControllerState = rest.state || {
    vault: undefined,
    nodeAuthTokens: undefined,
  };

  const controller = new SeedlessOnboardingController({
    encryptor,
    messenger,
    network: 'sapphire_devnet',
    state: initialState,
    ...rest,
  });
  const { toprfClient } = controller;

  return await fn({
    controller,
    encryptor,
    initialState: controller.state,
    messenger,
    toprfClient,
  });
}

/**
 * Builds a mock ToprfEncryptor.
 *
 * @returns The mock ToprfEncryptor.
 */
function createMockToprfEncryptor() {
  return new MockToprfEncryptorDecryptor();
}

/**
 * Mocks the createLocalEncKey method of the ToprfSecureBackup instance.
 *
 * @param toprfClient - The ToprfSecureBackup instance.
 * @param password - The mock password.
 *
 * @returns The mock createLocalEncKey result.
 */
function mockCreateLocalEncKey(
  toprfClient: ToprfSecureBackup,
  password: string,
) {
  const mockToprfEncryptor = createMockToprfEncryptor();

  const encKey = mockToprfEncryptor.keyFromPassword(password);
  const authKeyPair = mockToprfEncryptor.authKeyPairFromPassword(password);
  const oprfKey = BigInt(0);
  const seed = new Uint8Array(Buffer.from(password, 'utf-8'));

  jest.spyOn(toprfClient, 'createLocalEncKey').mockReturnValue({
    encKey,
    authKeyPair,
    oprfKey,
    seed,
  });

  return {
    encKey,
    authKeyPair,
    oprfKey,
    seed,
  };
}

/**
 * Mocks the recoverEncKey method of the ToprfSecureBackup instance.
 *
 * @param toprfClient - The ToprfSecureBackup instance.
 * @param password - The mock password.
 *
 * @returns The mock recoverEncKey result.
 */
function mockRecoverEncKey(
  toprfClient: ToprfSecureBackup,
  password: string,
): RecoverEncryptionKeyResult {
  const mockToprfEncryptor = createMockToprfEncryptor();

  const encKey = mockToprfEncryptor.keyFromPassword(password);
  const authKeyPair = mockToprfEncryptor.authKeyPairFromPassword(password);
  const rateLimitResetResult = Promise.resolve();

  jest.spyOn(toprfClient, 'recoverEncKey').mockResolvedValueOnce({
    encKey,
    authKeyPair,
    rateLimitResetResult,
    shareKeyIndex: 1,
  });

  return {
    encKey,
    authKeyPair,
    rateLimitResetResult,
    shareKeyIndex: 1,
  };
}

/**
 * Mocks the changeEncKey method of the ToprfSecureBackup instance.
 *
 * @param toprfClient - The ToprfSecureBackup instance.
 * @param newPassword - The new password.
 *
 * @returns The mock changeEncKey result.
 */
function mockChangeEncKey(
  toprfClient: ToprfSecureBackup,
  newPassword: string,
): ChangeEncryptionKeyResult {
  const mockToprfEncryptor = createMockToprfEncryptor();

  const encKey = mockToprfEncryptor.keyFromPassword(newPassword);
  const authKeyPair = mockToprfEncryptor.authKeyPairFromPassword(newPassword);

  jest.spyOn(toprfClient, 'changeEncKey').mockResolvedValueOnce({
    encKey,
    authKeyPair,
  });

  return { encKey, authKeyPair };
}

/**
 * Creates a mock vault.
 *
 * @param encKey - The encryption key.
 * @param authKeyPair - The authentication key pair.
 * @param MOCK_PASSWORD - The mock password.
 * @param authTokens - The authentication tokens.
 *
 * @returns The mock vault data.
 */
async function createMockVault(
  encKey: Uint8Array,
  authKeyPair: KeyPair,
  MOCK_PASSWORD: string,
  authTokens: NodeAuthTokens,
) {
  const encryptor = createMockVaultEncryptor();

  const serializedKeyData = JSON.stringify({
    authTokens,
    toprfEncryptionKey: Buffer.from(encKey).toString('base64'),
    toprfAuthKeyPair: JSON.stringify({
      sk: `0x${authKeyPair.sk.toString(16)}`,
      pk: Buffer.from(authKeyPair.pk).toString('base64'),
    }),
  });

  const encryptedMockVault = await encryptor.encrypt(
    MOCK_PASSWORD,
    serializedKeyData,
  );

  return encryptedMockVault;
}

/**
 * Decrypts the vault with the given password.
 *
 * @param vault - The vault.
 * @param password - The password.
 *
 * @returns The decrypted vault.
 */
async function decryptVault(vault: string, password: string) {
  const encryptor = createMockVaultEncryptor();

  const decryptedVault = await encryptor.decrypt(password, vault);

  const deserializedVault = JSON.parse(decryptedVault as string);

  const toprfEncryptionKey = new Uint8Array(
    Buffer.from(deserializedVault.toprfEncryptionKey, 'base64'),
  );
  const parsedToprfAuthKeyPair = JSON.parse(deserializedVault.toprfAuthKeyPair);
  const toprfAuthKeyPair = {
    sk: BigInt(parsedToprfAuthKeyPair.sk),
    pk: new Uint8Array(Buffer.from(parsedToprfAuthKeyPair.pk, 'base64')),
  };

  return {
    toprfEncryptionKey,
    toprfAuthKeyPair,
  };
}

const verifier = 'google';
const verifierId = 'user-test@gmail.com';
const idTokens = ['idToken'];

const MOCK_NODE_AUTH_TOKENS = [
  {
    authToken: 'authToken',
    nodeIndex: 1,
    nodePubKey: 'nodePubKey',
  },
  {
    authToken: 'authToken2',
    nodeIndex: 2,
    nodePubKey: 'nodePubKey2',
  },
  {
    authToken: 'authToken3',
    nodeIndex: 3,
    nodePubKey: 'nodePubKey3',
  },
];

const MOCK_SEED_PHRASE = new Uint8Array(
  Buffer.from(
    'horror pink muffin canal young photo magnet runway start elder patch until',
    'utf-8',
  ),
);

describe('SeedlessOnboardingController', () => {
  describe('constructor', () => {
    it('should be able to instantiate', () => {
      const messenger = buildSeedlessOnboardingControllerMessenger();
      const controller = new SeedlessOnboardingController({
        messenger,
      });
      expect(controller).toBeDefined();
      expect(controller.state).toStrictEqual({
        isNewUser: true,
      });
    });

    it('should be able to instantiate with an encryptor', () => {
      const messenger = buildSeedlessOnboardingControllerMessenger();
      const encryptor = createMockVaultEncryptor();

      expect(
        () =>
          new SeedlessOnboardingController({
            messenger,
            encryptor,
          }),
      ).not.toThrow();
    });
  });

  describe('authenticate', () => {
    it('should be able to register a new user', async () => {
      await withController(async ({ controller, toprfClient }) => {
        jest.spyOn(toprfClient, 'authenticate').mockResolvedValue({
          nodeAuthTokens: MOCK_NODE_AUTH_TOKENS,
          isNewUser: false,
        });

        const authResult = await controller.authenticate({
          idTokens,
          verifier,
          verifierId,
        });

        expect(authResult).toBeDefined();
        expect(authResult.nodeAuthTokens).toBeDefined();
        expect(authResult.isNewUser).toBe(false);

        expect(controller.state.nodeAuthTokens).toBeDefined();
        expect(controller.state.nodeAuthTokens).toStrictEqual(
          MOCK_NODE_AUTH_TOKENS,
        );
      });
    });

    it('should be able to authenticate an existing user', async () => {
      await withController(async ({ controller, toprfClient }) => {
        jest.spyOn(toprfClient, 'authenticate').mockResolvedValue({
          nodeAuthTokens: MOCK_NODE_AUTH_TOKENS,
          isNewUser: true,
        });

        const authResult = await controller.authenticate({
          idTokens,
          verifier,
          verifierId,
        });

        expect(authResult).toBeDefined();
        expect(authResult.nodeAuthTokens).toBeDefined();
        expect(authResult.isNewUser).toBe(true);

        expect(controller.state.nodeAuthTokens).toBeDefined();
        expect(controller.state.nodeAuthTokens).toStrictEqual(
          MOCK_NODE_AUTH_TOKENS,
        );
      });
    });

    it('should be able to authenticate with single id verifier', async () => {
      await withController(async ({ controller, toprfClient }) => {
        const aggregateVerifier = 'test-aggregate-verifier';
        const aggregateVerifierId = 'test-aggregate-verifier-id';
        const aggregateIdTokens = ['mock-aggregate-id-token'];
        const hashedAggregateIdTokens = ['hashed-mock-aggregate-id-token'];

        // mock the authentication method
        jest.spyOn(toprfClient, 'authenticate').mockResolvedValue({
          nodeAuthTokens: MOCK_NODE_AUTH_TOKENS,
          isNewUser: true,
        });

        const authResult = await controller.authenticate({
          idTokens: hashedAggregateIdTokens,
          verifier: aggregateVerifier,
          verifierId: aggregateVerifierId,
          singleIdVerifierParams: {
            subVerifier: verifier,
            subVerifierIdTokens: aggregateIdTokens,
          },
        });

        expect(authResult).toBeDefined();
        expect(authResult.nodeAuthTokens).toBeDefined();
        expect(authResult.isNewUser).toBe(true);

        expect(controller.state.nodeAuthTokens).toBeDefined();
        expect(controller.state.nodeAuthTokens).toStrictEqual(
          MOCK_NODE_AUTH_TOKENS,
        );
      });
    });

    it('should throw an error if the authentication fails', async () => {
      const JSONRPC_ERROR = {
        jsonrpc: '2.0',
        error: {
          code: -32000,
          message: 'Internal error',
        },
      };

      await withController(async ({ controller }) => {
        const handleCommitment = handleMockCommitment({
          status: 200,
          body: JSONRPC_ERROR,
        });
        const handleAuthentication = handleMockAuthenticate({
          status: 200,
          body: JSONRPC_ERROR,
        });
        await expect(
          controller.authenticate({
            idTokens,
            verifier,
            verifierId,
          }),
        ).rejects.toThrow(
          SeedlessOnboardingControllerError.AuthenticationError,
        );
        expect(handleCommitment.isDone()).toBe(true);
        expect(handleAuthentication.isDone()).toBe(false);
      });
    });
  });

  describe('createSeedPhraseBackup', () => {
    const MOCK_PASSWORD = 'mock-password';

    it('should be able to create a seed phrase backup', async () => {
      await withController(
        { state: { nodeAuthTokens: MOCK_NODE_AUTH_TOKENS } },
        async ({ controller, toprfClient, initialState, encryptor }) => {
          const { encKey, authKeyPair } = mockCreateLocalEncKey(
            toprfClient,
            MOCK_PASSWORD,
          );

          // persist the local enc key
          jest.spyOn(toprfClient, 'persistOprfKey').mockResolvedValueOnce();
          // encrypt and store the secret data
          const mockSecretDataAdd = handleMockSecretDataAdd();
          await controller.createSeedPhraseBackup({
            verifier,
            verifierId,
            seedPhrase: MOCK_SEED_PHRASE,
            password: MOCK_PASSWORD,
          });

          expect(mockSecretDataAdd.isDone()).toBe(true);

          expect(controller.state.vault).toBeDefined();
          expect(controller.state.vault).not.toBe(initialState.vault);
          expect(controller.state.vault).not.toStrictEqual({});

          // verify the vault data
          const encryptedMockVault = await createMockVault(
            encKey,
            authKeyPair,
            MOCK_PASSWORD,
            MOCK_NODE_AUTH_TOKENS,
          );

          const expectedVaultValue = await encryptor.decrypt(
            MOCK_PASSWORD,
            encryptedMockVault,
          );
          const resultedVaultValue = await encryptor.decrypt(
            MOCK_PASSWORD,
            controller.state.vault as string,
          );

          expect(expectedVaultValue).toStrictEqual(resultedVaultValue);
        },
      );
    });

    it('should throw an error if create encryption key fails', async () => {
      await withController(
        { state: { nodeAuthTokens: MOCK_NODE_AUTH_TOKENS } },
        async ({ controller, toprfClient, initialState }) => {
          jest
            .spyOn(toprfClient, 'createLocalEncKey')
            .mockImplementation(() => {
              throw new Error('Failed to create local encryption key');
            });

          await expect(
            controller.createSeedPhraseBackup({
              verifier,
              verifierId,
              seedPhrase: MOCK_SEED_PHRASE,
              password: MOCK_PASSWORD,
            }),
          ).rejects.toThrow('Failed to create local encryption key');

          // verify vault is not created
          expect(controller.state.vault).toBe(initialState.vault);
        },
      );
    });

    it('should throw an error if user does not have the AuthToken', async () => {
      await withController(async ({ controller, initialState }) => {
        await expect(
          controller.createSeedPhraseBackup({
            verifier,
            verifierId,
            seedPhrase: MOCK_SEED_PHRASE,
            password: MOCK_PASSWORD,
          }),
        ).rejects.toThrow(SeedlessOnboardingControllerError.NoOAuthIdToken);

        // verify vault is not created
        expect(controller.state.vault).toBe(initialState.vault);
      });
    });

    it('should throw an error if persistOprfKey fails', async () => {
      await withController(
        { state: { nodeAuthTokens: MOCK_NODE_AUTH_TOKENS } },
        async ({ controller, toprfClient }) => {
          mockCreateLocalEncKey(toprfClient, MOCK_PASSWORD);

          jest
            .spyOn(toprfClient, 'persistOprfKey')
            .mockRejectedValueOnce(
              new Error('Failed to persist local encryption key'),
            );

          const mockSecretDataAdd = handleMockSecretDataAdd();
          await expect(
            controller.createSeedPhraseBackup({
              verifier,
              verifierId,
              seedPhrase: MOCK_SEED_PHRASE,
              password: MOCK_PASSWORD,
            }),
          ).rejects.toThrow(
            SeedlessOnboardingControllerError.AuthenticationError,
          );

          expect(mockSecretDataAdd.isDone()).toBe(true);
        },
      );
    });
  });

  describe('fetchAndRestoreSeedPhrase', () => {
    const MOCK_PASSWORD = 'mock-password';

    it('should be able to restore and login with a seed phrase from metadata', async () => {
      await withController(
        { state: { nodeAuthTokens: MOCK_NODE_AUTH_TOKENS } },
        async ({ controller, toprfClient, initialState, encryptor }) => {
          // fetch and decrypt the secret data
          const { encKey, authKeyPair } = mockRecoverEncKey(
            toprfClient,
            MOCK_PASSWORD,
          );

          const mockSecretDataGet = handleMockSecretDataGet({
            status: 200,
            body: createMockSecretDataGetResponse(
              [MOCK_SEED_PHRASE],
              MOCK_PASSWORD,
            ),
          });
          const secretData = await controller.fetchAndRestoreSeedPhrase(
            verifier,
            verifierId,
            MOCK_PASSWORD,
          );

          expect(mockSecretDataGet.isDone()).toBe(true);
          expect(secretData).toBeDefined();
          expect(secretData).toStrictEqual([MOCK_SEED_PHRASE]);

          expect(controller.state.vault).toBeDefined();
          expect(controller.state.vault).not.toBe(initialState.vault);
          expect(controller.state.vault).not.toStrictEqual({});

          // verify the vault data
          const encryptedMockVault = await createMockVault(
            encKey,
            authKeyPair,
            MOCK_PASSWORD,
            MOCK_NODE_AUTH_TOKENS,
          );

          const expectedVaultValue = await encryptor.decrypt(
            MOCK_PASSWORD,
            encryptedMockVault,
          );
          const resultedVaultValue = await encryptor.decrypt(
            MOCK_PASSWORD,
            controller.state.vault as string,
          );

          expect(expectedVaultValue).toStrictEqual(resultedVaultValue);
        },
      );
    });

    it('should be able to restore multiple seed phrases from metadata', async () => {
      await withController(
        { state: { nodeAuthTokens: MOCK_NODE_AUTH_TOKENS } },
        async ({ controller, toprfClient, encryptor }) => {
          // fetch and decrypt the secret data
          const { encKey, authKeyPair } = mockRecoverEncKey(
            toprfClient,
            MOCK_PASSWORD,
          );

          const mockSecretDataGet = handleMockSecretDataGet({
            status: 200,
            body: createMockSecretDataGetResponse(
              MULTIPLE_MOCK_SEEDPHRASE_METADATA,
              MOCK_PASSWORD,
            ),
          });
          const secretData = await controller.fetchAndRestoreSeedPhrase(
            verifier,
            verifierId,
            MOCK_PASSWORD,
          );

          expect(mockSecretDataGet.isDone()).toBe(true);
          expect(secretData).toBeDefined();

          // `fetchAndRestoreSeedPhraseMetadata` should sort the seed phrases by timestamp and return the seed phrases in the correct order
          expect(secretData).toStrictEqual([
            new Uint8Array(Buffer.from('seedPhrase1', 'utf-8')),
            new Uint8Array(Buffer.from('seedPhrase2', 'utf-8')),
            new Uint8Array(Buffer.from('seedPhrase3', 'utf-8')),
          ]);

          // verify the vault data
          const encryptedMockVault = await createMockVault(
            encKey,
            authKeyPair,
            MOCK_PASSWORD,
            MOCK_NODE_AUTH_TOKENS,
          );

          const expectedVaultValue = await encryptor.decrypt(
            MOCK_PASSWORD,
            encryptedMockVault,
          );
          const resultedVaultValue = await encryptor.decrypt(
            MOCK_PASSWORD,
            controller.state.vault as string,
          );

          expect(expectedVaultValue).toStrictEqual(resultedVaultValue);
        },
      );
    });

    it('should throw an error if the key recovery failed', async () => {
      await withController(
        { state: { nodeAuthTokens: MOCK_NODE_AUTH_TOKENS } },
        async ({ controller, toprfClient }) => {
          jest
            .spyOn(toprfClient, 'recoverEncKey')
            .mockRejectedValueOnce(
              new Error('Failed to recover encryption key'),
            );

          await expect(
            controller.fetchAndRestoreSeedPhrase(
              verifier,
              verifierId,
              'INCORRECT_PASSWORD',
            ),
          ).rejects.toThrow(
            SeedlessOnboardingControllerError.AuthenticationError,
          );
        },
      );
    });

    it('should throw an error if incorrect password is provided', async () => {
      await withController(
        { state: { nodeAuthTokens: MOCK_NODE_AUTH_TOKENS } },
        async ({ controller, toprfClient }) => {
          mockRecoverEncKey(toprfClient, MOCK_PASSWORD);

          jest
            .spyOn(toprfClient, 'fetchAllSecretDataItems')
            .mockRejectedValueOnce(new Error('Failed to decrypt data'));

          await expect(
            controller.fetchAndRestoreSeedPhrase(
              verifier,
              verifierId,
              'INCORRECT_PASSWORD',
            ),
          ).rejects.toThrow('Failed to decrypt data');
        },
      );
    });

    it('should throw an error if the restored seed phrases are not in the correct shape', async () => {
      await withController(
        { state: { nodeAuthTokens: MOCK_NODE_AUTH_TOKENS } },
        async ({ controller, toprfClient }) => {
          mockRecoverEncKey(toprfClient, MOCK_PASSWORD);

          // mock the incorrect data shape
          jest
            .spyOn(toprfClient, 'fetchAllSecretDataItems')
            .mockResolvedValueOnce([
              new Uint8Array(
                Buffer.from(JSON.stringify({ key: 'value' }), 'utf-8'),
              ),
            ]);
          await expect(
            controller.fetchAndRestoreSeedPhrase(
              verifier,
              verifierId,
              MOCK_PASSWORD,
            ),
          ).rejects.toThrow(
            SeedlessOnboardingControllerError.InvalidSeedPhraseMetadata,
          );
        },
      );
    });
  });

  describe('updatePassword', () => {
    const MOCK_PASSWORD = 'mock-password';
    const NEW_MOCK_PASSWORD = 'new-mock-password';
    const MOCK_VAULT = JSON.stringify({ foo: 'bar' });

    it('should be able to update new password', async () => {
      await withController(
        { state: { nodeAuthTokens: MOCK_NODE_AUTH_TOKENS } },
        async ({ controller, toprfClient }) => {
          mockCreateLocalEncKey(toprfClient, MOCK_PASSWORD);

          // persist the local enc key
          jest.spyOn(toprfClient, 'persistOprfKey').mockResolvedValueOnce();
          // encrypt and store the secret data
          handleMockSecretDataAdd();
          await controller.createSeedPhraseBackup({
            verifier,
            verifierId,
            seedPhrase: MOCK_SEED_PHRASE,
            password: MOCK_PASSWORD,
          });

          // verify the vault data before update password
          expect(controller.state.vault).toBeDefined();
          const vaultBeforeUpdatePassword = controller.state.vault;
          const {
            toprfEncryptionKey: oldEncKey,
            toprfAuthKeyPair: oldAuthKeyPair,
          } = await decryptVault(
            vaultBeforeUpdatePassword as string,
            MOCK_PASSWORD,
          );

          // mock the recover enc key
          mockRecoverEncKey(toprfClient, MOCK_PASSWORD);

          // mock the change enc key
          const { encKey: newEncKey, authKeyPair: newAuthKeyPair } =
            mockChangeEncKey(toprfClient, NEW_MOCK_PASSWORD);

          await controller.changePassword({
            verifier,
            verifierId,
            newPassword: NEW_MOCK_PASSWORD,
            oldPassword: MOCK_PASSWORD,
          });

          // verify the vault after update password
          const vaultAfterUpdatePassword = controller.state.vault;
          const {
            toprfEncryptionKey: newEncKeyFromVault,
            toprfAuthKeyPair: newAuthKeyPairFromVault,
          } = await decryptVault(
            vaultAfterUpdatePassword as string,
            NEW_MOCK_PASSWORD,
          );

          // verify that the encryption key and auth key pair are updated
          expect(newEncKeyFromVault).not.toStrictEqual(oldEncKey);
          expect(newAuthKeyPairFromVault.sk).not.toStrictEqual(
            oldAuthKeyPair.sk,
          );
          expect(newAuthKeyPairFromVault.pk).not.toStrictEqual(
            oldAuthKeyPair.pk,
          );

          // verify the vault data is updated with the new encryption key and auth key pair
          expect(newEncKeyFromVault).toStrictEqual(newEncKey);
          expect(newAuthKeyPairFromVault.sk).toStrictEqual(newAuthKeyPair.sk);
          expect(newAuthKeyPairFromVault.pk).toStrictEqual(newAuthKeyPair.pk);
        },
      );
    });

    it('should throw an error if vault is missing', async () => {
      await withController(
        { state: { nodeAuthTokens: MOCK_NODE_AUTH_TOKENS } },
        async ({ controller }) => {
          await expect(
            controller.changePassword({
              verifier,
              verifierId,
              newPassword: NEW_MOCK_PASSWORD,
              oldPassword: MOCK_PASSWORD,
            }),
          ).rejects.toThrow(SeedlessOnboardingControllerError.VaultError);
        },
      );
    });

    it('should throw an error if vault unlocked has an unexpected shape', async () => {
      await withController(
        {
          state: {
            nodeAuthTokens: MOCK_NODE_AUTH_TOKENS,
            vault: MOCK_VAULT,
          },
        },
        async ({ controller, encryptor }) => {
          jest
            .spyOn(encryptor, 'decrypt')
            .mockResolvedValueOnce({ foo: 'bar' });
          await expect(
            controller.changePassword({
              verifier,
              verifierId,
              newPassword: NEW_MOCK_PASSWORD,
              oldPassword: MOCK_PASSWORD,
            }),
          ).rejects.toThrow(SeedlessOnboardingControllerError.VaultDataError);
        },
      );
    });

    it('should throw an error if vault unlocked has invalid authentication data', async () => {
      await withController(
        {
          state: {
            nodeAuthTokens: MOCK_NODE_AUTH_TOKENS,
            vault: MOCK_VAULT,
          },
        },
        async ({ controller, encryptor }) => {
          jest.spyOn(encryptor, 'decrypt').mockResolvedValueOnce(MOCK_VAULT);
          await expect(
            controller.changePassword({
              verifier,
              verifierId,
              newPassword: NEW_MOCK_PASSWORD,
              oldPassword: MOCK_PASSWORD,
            }),
          ).rejects.toThrow(SeedlessOnboardingControllerError.MissingVaultData);
        },
      );
    });

    it('should throw an error if the old password is incorrect', async () => {
      await withController(
        {
          state: {
            nodeAuthTokens: MOCK_NODE_AUTH_TOKENS,
            vault: MOCK_VAULT,
          },
        },
        async ({ controller, encryptor }) => {
          jest
            .spyOn(encryptor, 'decrypt')
            .mockRejectedValueOnce(new Error('Incorrect password'));
          await expect(
            controller.changePassword({
              verifier,
              verifierId,
              newPassword: NEW_MOCK_PASSWORD,
              oldPassword: 'INCORRECT_PASSWORD',
            }),
          ).rejects.toThrow('Incorrect password');
        },
      );
    });
  });

  describe('vault', () => {
    const MOCK_PASSWORD = 'mock-password';

    it('should not create a vault if the user does not have encrypted seed phrase metadata', async () => {
      await withController(
        { state: { nodeAuthTokens: MOCK_NODE_AUTH_TOKENS } },
        async ({ controller, initialState, toprfClient }) => {
          expect(initialState.vault).toBeUndefined();

          mockRecoverEncKey(toprfClient, MOCK_PASSWORD);

          const mockSecretDataGet = handleMockSecretDataGet({
            status: 200,
            body: {
              success: true,
              data: [],
            },
          });
          await controller.fetchAndRestoreSeedPhrase(
            verifier,
            verifierId,
            MOCK_PASSWORD,
          );

          expect(mockSecretDataGet.isDone()).toBe(true);
          expect(controller.state.vault).toBeUndefined();
          expect(controller.state.vault).toBe(initialState.vault);
        },
      );
    });

    it('should throw an error if the password is an empty string', async () => {
      await withController(
        { state: { nodeAuthTokens: MOCK_NODE_AUTH_TOKENS } },
        async ({ controller, toprfClient }) => {
          // create the local enc key
          mockCreateLocalEncKey(toprfClient, MOCK_PASSWORD);
          // persist the local enc key
          jest.spyOn(toprfClient, 'persistOprfKey').mockResolvedValueOnce();
          // mock the secret data add
          const mockSecretDataAdd = handleMockSecretDataAdd();
          await expect(
            controller.createSeedPhraseBackup({
              verifier,
              verifierId,
              password: '',
              seedPhrase: MOCK_SEED_PHRASE,
            }),
          ).rejects.toThrow(
            SeedlessOnboardingControllerError.InvalidEmptyPassword,
          );

          expect(mockSecretDataAdd.isDone()).toBe(true);
        },
      );
    });

    it('should throw an error if the passowrd is of wrong type', async () => {
      await withController(
        { state: { nodeAuthTokens: MOCK_NODE_AUTH_TOKENS } },
        async ({ controller, toprfClient }) => {
          // create the local enc key
          mockCreateLocalEncKey(toprfClient, MOCK_PASSWORD);
          // persist the local enc key
          jest.spyOn(toprfClient, 'persistOprfKey').mockResolvedValueOnce();
          // mock the secret data add
          const mockSecretDataAdd = handleMockSecretDataAdd();
          await expect(
            controller.createSeedPhraseBackup({
              verifier,
              verifierId,
              // @ts-expect-error we are testing wrong password type
              password: 123,
              seedPhrase: MOCK_SEED_PHRASE,
            }),
          ).rejects.toThrow(
            SeedlessOnboardingControllerError.WrongPasswordType,
          );

          expect(mockSecretDataAdd.isDone()).toBe(true);
        },
      );
    });
  });
});

import type { ToprfSecureBackup } from '@metamask/toprf-secure-backup';
import { utf8ToBytes } from '@noble/ciphers/utils';

import { SeedlessOnboardingControllerError } from './constants';
import type {
  SeedlessOnboardingControllerMessenger,
  SeedlessOnboardingControllerOptions,
  SeedlessOnboardingControllerState,
} from './SeedlessOnboardingController';
import { SeedlessOnboardingController } from './SeedlessOnboardingController';
import {
  handleMockCommitment,
  handleMockAuthenticate,
  handleMockSecretDataGet,
  handleMockSecretDataAdd,
} from '../tests/__fixtures__/topfClient';
import { MockToprfEncryptorDecryptor } from '../tests/mocks/encryption';
import MockVaultEncryptor from '../tests/mocks/mockEncryptor';

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
 * Builds a mock encryptor.
 *
 * @returns The mock encryptor.
 */
function createMockEncryptor() {
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

const MOCK_SEED_PHRASE =
  'horror pink muffin canal young photo magnet runway start elder patch until';

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
      const encryptor = createMockEncryptor();

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
          verifierID: verifierId,
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
          verifierID: verifierId,
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
      await withController(async ({ controller }) => {
        const handleCommitment = handleMockCommitment();
        const handleAuthentication = handleMockAuthenticate();
        await expect(
          controller.authenticate({
            idTokens,
            verifier,
            verifierID: verifierId,
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
    const mockToprfEncryptor = createMockToprfEncryptor();

    it('should throw an error if user does not have the AuthToken', async () => {
      await withController(async ({ controller }) => {
        await expect(
          controller.createSeedPhraseBackup({
            verifier,
            verifierId,
            seedPhrase: MOCK_SEED_PHRASE,
            password: MOCK_PASSWORD,
          }),
        ).rejects.toThrow(SeedlessOnboardingControllerError.NoOAuthIdToken);
      });
    });

    it('should throw an error if create encryption key fails', async () => {
      await withController(
        { state: { nodeAuthTokens: MOCK_NODE_AUTH_TOKENS } },
        async ({ controller, toprfClient }) => {
          jest
            .spyOn(toprfClient, 'createEncKey')
            .mockRejectedValue(new Error('Failed to create encryption key'));

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
        },
      );
    });

    it('should be able to create a seed phrase backup', async () => {
      await withController(
        { state: { nodeAuthTokens: MOCK_NODE_AUTH_TOKENS } },
        async ({ controller, toprfClient }) => {
          jest.spyOn(toprfClient, 'createEncKey').mockResolvedValueOnce({
            encKey: mockToprfEncryptor.keyFromPassword(MOCK_PASSWORD),
            authKeyPair:
              mockToprfEncryptor.authKeyPairFromPassword(MOCK_PASSWORD),
          });

          // encrypt and store the secret data
          const mockSecretDataAdd = handleMockSecretDataAdd();
          await controller.createSeedPhraseBackup({
            verifier,
            verifierId,
            seedPhrase: MOCK_SEED_PHRASE,
            password: MOCK_PASSWORD,
          });

          expect(mockSecretDataAdd.isDone()).toBe(true);

          // fetch and decrypt the secret data
          jest.spyOn(toprfClient, 'recoverEncKey').mockResolvedValueOnce({
            encKey: mockToprfEncryptor.keyFromPassword(MOCK_PASSWORD),
            authKeyPair:
              mockToprfEncryptor.authKeyPairFromPassword(MOCK_PASSWORD),
            rateLimitResetResult: Promise.resolve(),
          });
          const mockSecretDataGet = handleMockSecretDataGet({
            status: 200,
            body: {
              success: true,
              data: [
                mockToprfEncryptor.encrypt(
                  mockToprfEncryptor.keyFromPassword(MOCK_PASSWORD),
                  utf8ToBytes(MOCK_SEED_PHRASE),
                ),
              ],
            },
          });
          const secretData = await controller.fetchAndRestoreSeedPhraseMetadata(
            verifier,
            verifierId,
            MOCK_PASSWORD,
          );

          expect(mockSecretDataGet.isDone()).toBe(true);
          expect(secretData).toBeDefined();
          expect(secretData).toStrictEqual([utf8ToBytes(MOCK_SEED_PHRASE)]);
        },
      );
    });
  });

  describe('fetchAndRestoreSeedPhraseMetadata', () => {
    const mockToprfEncryptor = createMockToprfEncryptor();
    const MOCK_PASSWORD = 'mock-password';

    it('should be able to restore and login with a seed phrase from metadata', async () => {
      await withController(
        { state: { nodeAuthTokens: MOCK_NODE_AUTH_TOKENS } },
        async ({ controller, toprfClient }) => {
          // fetch and decrypt the secret data
          jest.spyOn(toprfClient, 'recoverEncKey').mockResolvedValueOnce({
            encKey: mockToprfEncryptor.keyFromPassword(MOCK_PASSWORD),
            authKeyPair:
              mockToprfEncryptor.authKeyPairFromPassword(MOCK_PASSWORD),
            rateLimitResetResult: Promise.resolve(),
          });
          const mockSecretDataGet = handleMockSecretDataGet({
            status: 200,
            body: {
              success: true,
              data: [
                mockToprfEncryptor.encrypt(
                  mockToprfEncryptor.keyFromPassword(MOCK_PASSWORD),
                  utf8ToBytes(MOCK_SEED_PHRASE),
                ),
              ],
            },
          });
          const secretData = await controller.fetchAndRestoreSeedPhraseMetadata(
            verifier,
            verifierId,
            MOCK_PASSWORD,
          );

          expect(mockSecretDataGet.isDone()).toBe(true);
          expect(secretData).toBeDefined();
          expect(secretData).toStrictEqual([utf8ToBytes(MOCK_SEED_PHRASE)]);
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
            controller.fetchAndRestoreSeedPhraseMetadata(
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
          jest.spyOn(toprfClient, 'recoverEncKey').mockResolvedValueOnce({
            encKey: mockToprfEncryptor.keyFromPassword(MOCK_PASSWORD),
            authKeyPair:
              mockToprfEncryptor.authKeyPairFromPassword(MOCK_PASSWORD),
            rateLimitResetResult: Promise.resolve(),
          });

          jest
            .spyOn(toprfClient, 'fetchAllSecretDataItems')
            .mockRejectedValueOnce(new Error('Failed to decrypt data'));

          await expect(
            controller.fetchAndRestoreSeedPhraseMetadata(
              verifier,
              verifierId,
              'INCORRECT_PASSWORD',
            ),
          ).rejects.toThrow(
            SeedlessOnboardingControllerError.IncorrectPassword,
          );
        },
      );
    });
  });

  describe('#createNewVaultWithAuthData', () => {
    const MOCK_PASSWORD = 'mock-password';
    const mockToprfEncryptor = createMockToprfEncryptor();

    it('should create a vault after seedless backup', async () => {
      await withController(
        { state: { nodeAuthTokens: MOCK_NODE_AUTH_TOKENS } },
        async ({ controller, initialState, toprfClient, encryptor }) => {
          expect(initialState.vault).toBeUndefined();

          const mockEncKey = mockToprfEncryptor.keyFromPassword(MOCK_PASSWORD);
          const mockAuthKeyPair =
            mockToprfEncryptor.authKeyPairFromPassword(MOCK_PASSWORD);

          jest.spyOn(toprfClient, 'createEncKey').mockResolvedValueOnce({
            encKey: mockEncKey,
            authKeyPair: mockAuthKeyPair,
          });

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

          const serializedKeyData = JSON.stringify({
            authTokens: MOCK_NODE_AUTH_TOKENS,
            toprfEncryptionKey: Buffer.from(mockEncKey).toString('base64'),
            toprfAuthKeyPair: JSON.stringify({
              sk: mockAuthKeyPair.sk.toString(),
              pk: Buffer.from(mockAuthKeyPair.pk).toString('base64'),
            }),
          });

          const mockEncVault = await encryptor.encrypt(
            MOCK_PASSWORD,
            serializedKeyData,
          );

          const expectedVaultValue = await encryptor.decrypt(
            MOCK_PASSWORD,
            mockEncVault,
          );
          const resultedVaultValue = await encryptor.decrypt(
            MOCK_PASSWORD,
            controller.state.vault as string,
          );

          expect(expectedVaultValue).toStrictEqual(serializedKeyData);
          expect(resultedVaultValue).toStrictEqual(serializedKeyData);
        },
      );
    });

    it('should create a vault after fetching and restoring seed phrase metadata', async () => {
      await withController(
        { state: { nodeAuthTokens: MOCK_NODE_AUTH_TOKENS } },
        async ({ controller, initialState, toprfClient }) => {
          expect(initialState.vault).toBeUndefined();

          const mockEncKey = mockToprfEncryptor.keyFromPassword(MOCK_PASSWORD);
          const mockAuthKeyPair =
            mockToprfEncryptor.authKeyPairFromPassword(MOCK_PASSWORD);

          jest.spyOn(toprfClient, 'recoverEncKey').mockResolvedValueOnce({
            encKey: mockEncKey,
            authKeyPair: mockAuthKeyPair,
            rateLimitResetResult: Promise.resolve(),
          });

          const mockSecretDataGet = handleMockSecretDataGet({
            status: 200,
            body: {
              success: true,
              data: [
                mockToprfEncryptor.encrypt(
                  mockToprfEncryptor.keyFromPassword(MOCK_PASSWORD),
                  utf8ToBytes(MOCK_SEED_PHRASE),
                ),
              ],
            },
          });
          const secretData = await controller.fetchAndRestoreSeedPhraseMetadata(
            verifier,
            verifierId,
            MOCK_PASSWORD,
          );

          expect(mockSecretDataGet.isDone()).toBe(true);
          expect(secretData).toBeDefined();
          expect(secretData).toStrictEqual([utf8ToBytes(MOCK_SEED_PHRASE)]);

          expect(controller.state.vault).toBeDefined();
          expect(controller.state.vault).not.toBe(initialState.vault);
        },
      );
    });

    it('should not create a vault if the user does not have encrypted seed phrase metadata', async () => {
      await withController(
        { state: { nodeAuthTokens: MOCK_NODE_AUTH_TOKENS } },
        async ({ controller, initialState, toprfClient }) => {
          expect(initialState.vault).toBeUndefined();

          const mockEncKey = mockToprfEncryptor.keyFromPassword(MOCK_PASSWORD);
          const mockAuthKeyPair =
            mockToprfEncryptor.authKeyPairFromPassword(MOCK_PASSWORD);

          jest.spyOn(toprfClient, 'recoverEncKey').mockResolvedValueOnce({
            encKey: mockEncKey,
            authKeyPair: mockAuthKeyPair,
            rateLimitResetResult: Promise.resolve(),
          });

          const mockSecretDataGet = handleMockSecretDataGet({
            status: 200,
            body: {
              success: true,
              data: [],
            },
          });
          await controller.fetchAndRestoreSeedPhraseMetadata(
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
  });
});

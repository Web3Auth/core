import { utf8ToBytes } from '@noble/ciphers/utils';

import { SeedlessOnboardingControllerError } from './constants';
import { EncryptorDecryptor } from './encryption';
import type {
  SeedlessOnboardingControllerMessenger,
  SeedlessOnboardingControllerOptions,
  SeedlessOnboardingControllerState,
} from './SeedlessOnboardingController';
import { SeedlessOnboardingController } from './SeedlessOnboardingController';
import type { NodeAuthTokens } from './types';
import {
  handleMockAuthGet,
  handleMockAuthSet,
  handleMockMetadataGet,
  handleMockMetadataSet,
} from '../tests/__fixtures__/topfClient';
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
    state: initialState,
    ...rest,
  });

  return await fn({
    controller,
    encryptor,
    initialState: controller.state,
    messenger,
  });
}

/**
 * Builds a mock ToprfEncryptor.
 *
 * @returns The mock ToprfEncryptor.
 */
function createMockToprfEncryptor() {
  return new EncryptorDecryptor();
}

const verifier = 'google';
const verifierID = 'user-test@gmail.com';
const idTokens = ['idToken'];
const endpoints = ['https://example.com'];
const indexes = [1];
const MOCK_SEED_PHRASE = utf8ToBytes(
  'horror pink muffin canal young photo magnet runway start elder patch until',
);

const MOCK_NODE_AUTH_TOKENS = [
  { nodeAuthToken: 'nodeAuthToken', nodeIndex: 0 },
  { nodeAuthToken: 'nodeAuthToken2', nodeIndex: 1 },
];

describe('SeedlessOnboardingController', () => {
  describe('constructor', () => {
    it('should be able to instantiate', () => {
      const messenger = buildSeedlessOnboardingControllerMessenger();
      const controller = new SeedlessOnboardingController({
        messenger,
      });
      expect(controller).toBeDefined();
      expect(controller.state).toStrictEqual({
        hasValidEncryptionKey: false,
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
    const encryptor = createMockEncryptor();
    const messenger = buildSeedlessOnboardingControllerMessenger();
    const controller = new SeedlessOnboardingController({
      messenger,
      encryptor,
    });

    it('should be able to register a new user', async () => {
      const mockAuthGet = handleMockAuthGet({
        status: 200,
        body: { success: true },
      });
      const mockAuthSet = handleMockAuthSet();

      const authResult = await controller.authenticateOAuthUser({
        idTokens,
        verifier,
        verifierID,
        endpoints,
        indexes,
      });

      expect(mockAuthGet.isDone()).toBe(true);
      expect(mockAuthSet.isDone()).toBe(true);

      expect(authResult).toBeDefined();
      expect(authResult.nodeAuthTokens).toBeDefined();
      expect(authResult.hasValidEncKey).toBe(false);
    });

    it('should be able to authenticate an existing user', async () => {
      const mockAuthGet = handleMockAuthGet({
        status: 200,
        body: {
          success: true,
          data: JSON.stringify({
            nodeAuthTokens: [],
            hasValidEncKey: true,
          }),
        },
      });
      const mockAuthSet = handleMockAuthSet();

      const authResult = await controller.authenticateOAuthUser({
        idTokens,
        verifier,
        verifierID,
        endpoints,
        indexes,
      });

      expect(mockAuthGet.isDone()).toBe(true);
      expect(mockAuthSet.isDone()).toBe(false);

      expect(authResult).toBeDefined();
      expect(authResult.nodeAuthTokens).toBeDefined();
      expect(authResult.hasValidEncKey).toBe(true);
    });
  });

  describe('createSeedPhraseBackup', () => {
    const MOCK_PASSWORD = 'mock-password';
    const mockToprfEncryptor = createMockToprfEncryptor();

    it('should be able to create a seed phrase backup', async () => {
      await withController(async ({ controller }) => {
        const mockAuthGet = handleMockAuthGet();
        const mockAuthSet = handleMockAuthSet();

        await controller.authenticateOAuthUser({
          idTokens,
          verifier,
          verifierID,
          endpoints,
          indexes,
        });

        expect(mockAuthGet.isDone()).toBe(true);
        expect(mockAuthSet.isDone()).toBe(true);

        // encrypt and store the secret data
        const mockMetadataSet = handleMockMetadataSet();
        await controller.createSeedPhraseBackup({
          verifier,
          verifierID,
          seedPhrase: MOCK_SEED_PHRASE,
          password: MOCK_PASSWORD,
        });

        expect(mockAuthGet.isDone()).toBe(true);
        expect(mockAuthSet.isDone()).toBe(true);
        expect(mockMetadataSet.isDone()).toBe(true);

        // fetch and decrypt the secret data
        const mockMetadataGet = handleMockMetadataGet({
          status: 200,
          body: {
            success: true,
            data: [
              mockToprfEncryptor.encrypt(
                mockToprfEncryptor.keyFromPassword(MOCK_PASSWORD),
                MOCK_SEED_PHRASE,
              ),
            ],
          },
        });
        const secretData = await controller.fetchAndRestoreSeedPhraseMetadata(
          verifier,
          verifierID,
          MOCK_PASSWORD,
        );

        expect(mockMetadataGet.isDone()).toBe(true);
        expect(secretData).toBeDefined();
        expect(secretData).toStrictEqual([MOCK_SEED_PHRASE]);
      });
    });

    it('should throw an error if user does not have the AuthToken', async () => {
      await withController(async ({ controller }) => {
        await expect(
          controller.createSeedPhraseBackup({
            verifier,
            verifierID,
            seedPhrase: MOCK_SEED_PHRASE,
            password: MOCK_PASSWORD,
          }),
        ).rejects.toThrow(SeedlessOnboardingControllerError.NoOAuthIdToken);
      });
    });
  });

  describe('fetchAndRestoreSeedPhraseMetadata', () => {
    const mockToprfEncryptor = createMockToprfEncryptor();
    const MOCK_PASSWORD = 'mock-password';
    const MOCK_ENCRYPTED_SRPS = [
      mockToprfEncryptor.encrypt(
        mockToprfEncryptor.keyFromPassword(MOCK_PASSWORD),
        MOCK_SEED_PHRASE,
      ),
    ];

    it('should be able to restore and login with a seed phrase from metadata', async () => {
      await withController(
        {
          state: {
            nodeAuthTokens: MOCK_NODE_AUTH_TOKENS,
          },
        },
        async ({ controller }) => {
          const mockAuthSet = handleMockAuthSet();
          const mockMetadataSet = handleMockMetadataSet();
          await controller.createSeedPhraseBackup({
            verifier,
            verifierID,
            seedPhrase: MOCK_SEED_PHRASE,
            password: MOCK_PASSWORD,
          });

          expect(mockAuthSet.isDone()).toBe(true);
          expect(mockMetadataSet.isDone()).toBe(true);

          const mockMetadataGet = handleMockMetadataGet({
            status: 200,
            body: {
              success: true,
              data: MOCK_ENCRYPTED_SRPS,
            },
          });
          const secretData = await controller.fetchAndRestoreSeedPhraseMetadata(
            verifier,
            verifierID,
            MOCK_PASSWORD,
          );

          expect(mockMetadataGet.isDone()).toBe(true);
          expect(secretData).toBeDefined();
          expect(secretData).toStrictEqual([MOCK_SEED_PHRASE]);
        },
      );
    });

    it('should be able to create a seed phrase metadata if it does not exist during login', async () => {
      await withController(async ({ controller }) => {
        const newVerifier = 'google';
        const newVerifierID = 'newUser@gmail.com';
        const mockAuthGet = handleMockAuthGet();
        const mockAuthSet = handleMockAuthSet();

        await controller.authenticateOAuthUser({
          idTokens,
          verifier: newVerifier,
          verifierID: newVerifierID,
          endpoints,
          indexes,
        });

        expect(mockAuthGet.isDone()).toBe(true);
        expect(mockAuthSet.isDone()).toBe(true);

        const mockMetadataGet = handleMockMetadataGet({
          status: 200,
          body: { success: true },
        });
        let secretData = await controller.fetchAndRestoreSeedPhraseMetadata(
          newVerifier,
          newVerifierID,
          MOCK_PASSWORD,
        );

        expect(mockMetadataGet.isDone()).toBe(true);
        expect(secretData).toBeDefined();
        // if the secret data is not found, it should return an empty array
        expect(secretData).toStrictEqual([]);

        const mockMetadataSet = handleMockMetadataSet();
        await controller.createSeedPhraseBackup({
          verifier: newVerifier,
          verifierID: newVerifierID,
          seedPhrase: MOCK_SEED_PHRASE,
          password: MOCK_PASSWORD,
        });

        expect(mockMetadataSet.isDone()).toBe(true);

        const mockMetadataGet2 = handleMockMetadataGet({
          status: 200,
          body: {
            success: true,
            data: MOCK_ENCRYPTED_SRPS,
          },
        });
        secretData = await controller.fetchAndRestoreSeedPhraseMetadata(
          newVerifier,
          newVerifierID,
          MOCK_PASSWORD,
        );

        expect(mockMetadataGet2.isDone()).toBe(true);
        expect(secretData).toBeDefined();
        expect(secretData).toStrictEqual([MOCK_SEED_PHRASE]);
      });
    });

    it('should throw an error if the user does not have correct password', async () => {
      await withController(
        {
          state: {
            nodeAuthTokens: MOCK_NODE_AUTH_TOKENS,
          },
        },
        async ({ controller }) => {
          const mockAuthSet = handleMockAuthSet();
          const mockMetadataSet = handleMockMetadataSet();
          await controller.createSeedPhraseBackup({
            verifier,
            verifierID,
            seedPhrase: MOCK_SEED_PHRASE,
            password: MOCK_PASSWORD,
          });

          expect(mockAuthSet.isDone()).toBe(true);
          expect(mockMetadataSet.isDone()).toBe(true);

          const mockMetadataGet = handleMockMetadataGet({
            status: 200,
            body: {
              success: true,
              data: MOCK_ENCRYPTED_SRPS,
            },
          });
          await expect(
            controller.fetchAndRestoreSeedPhraseMetadata(
              verifier,
              verifierID,
              'INCORRECT_PASSWORD',
            ),
          ).rejects.toThrow(
            SeedlessOnboardingControllerError.IncorrectPassword,
          );
          expect(mockMetadataGet.isDone()).toBe(true);
        },
      );
    });
  });

  describe('updatePassword', () => {
    const NEW_PASSWORD = 'new-password';
    const OLD_PASSWORD = 'old-password';

    it('should throw an error if the vault does not exist', async () => {
      await withController(async ({ controller }) => {
        await expect(
          controller.updatePassword({
            verifier,
            verifierID,
            newPassword: NEW_PASSWORD,
            oldPassword: OLD_PASSWORD,
          }),
        ).rejects.toThrow(SeedlessOnboardingControllerError.VaultError);
      });
    });

    it('should throw an error if the user does not have correct password', async () => {
      await withController(
        {
          state: {
            nodeAuthTokens: MOCK_NODE_AUTH_TOKENS,
          },
        },
        async ({ controller }) => {
          // encrypt and store the secret data
          const mockAuthSet = handleMockAuthSet();
          const mockMetadataSet = handleMockMetadataSet();
          await controller.createSeedPhraseBackup({
            verifier,
            verifierID,
            seedPhrase: MOCK_SEED_PHRASE,
            password: OLD_PASSWORD,
          });

          expect(mockAuthSet.isDone()).toBe(true);
          expect(mockMetadataSet.isDone()).toBe(true);

          await expect(
            controller.updatePassword({
              verifier,
              verifierID,
              newPassword: NEW_PASSWORD,
              oldPassword: 'INCORRECT_PASSWORD',
            }),
          ).rejects.toThrow(
            SeedlessOnboardingControllerError.IncorrectPassword,
          );
        },
      );
    });

    it('should throw an error if decrypted vault data is of unexpected shape', async () => {
      const mockNodeAuthTokens: NodeAuthTokens = [
        {
          nodeAuthToken: 'nodeAuthToken',
          nodeIndex: 0,
        },
      ];

      await withController(
        {
          state: { nodeAuthTokens: mockNodeAuthTokens, vault: 'vault' },
        },
        async ({ controller, encryptor }) => {
          handleMockAuthSet();
          handleMockMetadataSet();

          jest.spyOn(encryptor, 'decrypt').mockResolvedValueOnce(false);

          await expect(
            controller.updatePassword({
              verifier,
              verifierID,
              newPassword: NEW_PASSWORD,
              oldPassword: 'INCORRECT_PASSWORD',
            }),
          ).rejects.toThrow(SeedlessOnboardingControllerError.VaultDataError);

          jest
            .spyOn(encryptor, 'decrypt')
            .mockResolvedValueOnce(JSON.stringify({ key: 'value' }));
          await expect(
            controller.updatePassword({
              verifier,
              verifierID,
              newPassword: NEW_PASSWORD,
              oldPassword: 'INCORRECT_PASSWORD',
            }),
          ).rejects.toThrow(SeedlessOnboardingControllerError.VaultDataError);
        },
      );
    });

    it('should be able to update the password', async () => {
      await withController(
        {
          state: { nodeAuthTokens: MOCK_NODE_AUTH_TOKENS },
        },
        async ({ controller }) => {
          // encrypt and store the secret data
          const mockAuthSet = handleMockAuthSet();
          const mockMetadataSet = handleMockMetadataSet();
          await controller.createSeedPhraseBackup({
            verifier,
            verifierID,
            seedPhrase: MOCK_SEED_PHRASE,
            password: OLD_PASSWORD,
          });

          const vaultBeforeUpdatePwd = controller.state.vault;

          expect(mockAuthSet.isDone()).toBe(true);
          expect(mockMetadataSet.isDone()).toBe(true);

          await controller.updatePassword({
            verifier,
            verifierID,
            newPassword: NEW_PASSWORD,
            oldPassword: OLD_PASSWORD,
          });

          const vaultAfterUpdatePwd = controller.state.vault;

          expect(vaultAfterUpdatePwd).not.toBe(vaultBeforeUpdatePwd);
        },
      );
    });

    it('should throw an error if the password is an empty string', async () => {
      await withController(
        {
          state: { nodeAuthTokens: MOCK_NODE_AUTH_TOKENS },
        },
        async ({ controller }) => {
          await expect(
            controller.updatePassword({
              verifier,
              verifierID,
              newPassword: NEW_PASSWORD,
              oldPassword: '',
            }),
          ).rejects.toThrow(
            SeedlessOnboardingControllerError.InvalidEmptyPassword,
          );
        },
      );
    });

    it('should throw an error if the password is of wrong type', async () => {
      await withController(
        {
          state: { nodeAuthTokens: MOCK_NODE_AUTH_TOKENS },
        },
        async ({ controller }) => {
          await expect(
            controller.updatePassword({
              verifier,
              verifierID,
              newPassword: NEW_PASSWORD,
              // @ts-expect-error invalid password
              oldPassword: 123,
            }),
          ).rejects.toThrow(
            SeedlessOnboardingControllerError.WrongPasswordType,
          );
        },
      );
    });
  });

  describe('#createNewVaultWithAuthData', () => {
    const MOCK_PASSWORD = 'mock-password';

    it('should create a vault after seedless backup', async () => {
      await withController(
        {
          state: { nodeAuthTokens: MOCK_NODE_AUTH_TOKENS },
        },
        async ({ controller, initialState }) => {
          expect(initialState.vault).toBeUndefined();

          const mockAuthSet = handleMockAuthSet();
          const mockMetadataSet = handleMockMetadataSet();
          await controller.createSeedPhraseBackup({
            verifier,
            verifierID,
            seedPhrase: MOCK_SEED_PHRASE,
            password: MOCK_PASSWORD,
          });

          expect(mockAuthSet.isDone()).toBe(true);
          expect(mockMetadataSet.isDone()).toBe(true);

          expect(controller.state.vault).toBeDefined();
          expect(controller.state.vault).not.toBe(initialState.vault);
        },
      );
    });

    it('should create a vault after fetching and restoring seed phrase metadata', async () => {
      await withController(
        {
          state: { nodeAuthTokens: MOCK_NODE_AUTH_TOKENS },
        },
        async ({ controller, initialState }) => {
          const mockToprfEncryptor = createMockToprfEncryptor();
          expect(initialState.vault).toBeUndefined();

          const mockAuthSet = handleMockAuthSet();
          const mockMetadataGet = handleMockMetadataGet({
            status: 200,
            body: {
              success: true,
              data: [
                mockToprfEncryptor.encrypt(
                  mockToprfEncryptor.keyFromPassword(MOCK_PASSWORD),
                  MOCK_SEED_PHRASE,
                ),
              ],
            },
          });

          await controller.fetchAndRestoreSeedPhraseMetadata(
            verifier,
            verifierID,
            MOCK_PASSWORD,
          );

          expect(mockAuthSet.isDone()).toBe(true);
          expect(mockMetadataGet.isDone()).toBe(true);
          expect(controller.state.vault).toBeDefined();
          expect(controller.state.vault).not.toBe(initialState.vault);
        },
      );
    });

    it('should not create a vault if the user does not have encrypted seed phrase metadata', async () => {
      await withController(async ({ controller, initialState }) => {
        expect(initialState.vault).toBeUndefined();

        const mockAuthGet = handleMockAuthGet();
        const mockAuthSet = handleMockAuthSet();
        await controller.authenticateOAuthUser({
          idTokens,
          verifier,
          verifierID,
          endpoints,
          indexes,
        });

        expect(mockAuthGet.isDone()).toBe(true);
        expect(mockAuthSet.isDone()).toBe(true);

        const mockMetadataGet = handleMockMetadataGet({
          status: 200,
          body: {
            success: true,
            data: [],
          },
        });
        await controller.fetchAndRestoreSeedPhraseMetadata(
          verifier,
          verifierID,
          MOCK_PASSWORD,
        );

        expect(mockMetadataGet.isDone()).toBe(true);
        expect(controller.state.vault).toBeUndefined();
        expect(controller.state.vault).toBe(initialState.vault);
      });
    });
  });
});

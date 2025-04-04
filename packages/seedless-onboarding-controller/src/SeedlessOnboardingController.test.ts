import { SeedlessOnboardingControllerError } from './constants';
import { EncryptorDecryptor } from './encryption';
import type {
  SeedlessOnboardingControllerMessenger,
  SeedlessOnboardingControllerOptions,
  SeedlessOnboardingControllerState,
} from './SeedlessOnboardingController';
import { SeedlessOnboardingController } from './SeedlessOnboardingController';
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
  const controller = new SeedlessOnboardingController({
    encryptor,
    messenger,
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
      const mockAuthGet = handleMockAuthGet();
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
      expect(authResult.hasValidEncKey).toBe(false);
    });
  });

  describe('createSeedPhraseBackup', () => {
    const MOCK_PASSWORD = 'mock-password';

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
        expect(mockAuthSet.isDone()).toBe(false);

        const mockMetadataSet = handleMockMetadataSet();
        const seedPhraseBackup = await controller.createSeedPhraseBackup({
          verifier,
          verifierID,
          seedPhrase: MOCK_SEED_PHRASE,
          password: MOCK_PASSWORD,
        });

        expect(mockAuthGet.isDone()).toBe(true);
        expect(mockAuthSet.isDone()).toBe(true);
        expect(mockMetadataSet.isDone()).toBe(true);
        expect(seedPhraseBackup).toBeDefined();

        const encryptorDecryptor = new EncryptorDecryptor();
        const encryptedString = seedPhraseBackup.encryptedSeedPhrase;
        const decryptionKey = encryptorDecryptor.keyFromPassword(MOCK_PASSWORD);
        const decryptedString = encryptorDecryptor.decrypt(
          decryptionKey,
          encryptedString,
        );
        expect(decryptedString).toBe(MOCK_SEED_PHRASE);
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

  describe('restoreAndLoginWithSeedPhrase', () => {
    const mockToprfEncryptor = createMockToprfEncryptor();
    const MOCK_PASSWORD = 'mock-password';

    it('should be able to restore and login with a seed phrase from metadata', async () => {
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
        expect(mockAuthSet.isDone()).toBe(false);

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

        const mockMetadataGet = handleMockMetadataGet({
          status: 200,
          body: {
            success: true,
            message: mockToprfEncryptor.encrypt(
              mockToprfEncryptor.keyFromPassword(MOCK_PASSWORD),
              MOCK_SEED_PHRASE,
            ),
          },
        });
        const seedPhraseMetadata =
          await controller.fetchAndRestoreSeedPhraseMetadata(
            verifier,
            verifierID,
            MOCK_PASSWORD,
          );

        expect(mockMetadataGet.isDone()).toBe(true);
        expect(seedPhraseMetadata).toBeDefined();
        expect(seedPhraseMetadata.secretData).toBeDefined();
        expect(seedPhraseMetadata.secretData?.[0]).toBe(MOCK_SEED_PHRASE);
      });
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
        expect(mockAuthSet.isDone()).toBe(false);

        const mockMetadataGet = handleMockMetadataGet({
          status: 200,
          body: { success: true },
        });
        let seedPhraseMetadataFromMetadataStore =
          await controller.fetchAndRestoreSeedPhraseMetadata(
            newVerifier,
            newVerifierID,
            MOCK_PASSWORD,
          );

        expect(mockMetadataGet.isDone()).toBe(true);
        expect(seedPhraseMetadataFromMetadataStore).toBeDefined();
        expect(seedPhraseMetadataFromMetadataStore.secretData).toBeNull();

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
            message: mockToprfEncryptor.encrypt(
              mockToprfEncryptor.keyFromPassword(MOCK_PASSWORD),
              MOCK_SEED_PHRASE,
            ),
          },
        });
        seedPhraseMetadataFromMetadataStore =
          await controller.fetchAndRestoreSeedPhraseMetadata(
            newVerifier,
            newVerifierID,
            MOCK_PASSWORD,
          );

        expect(mockMetadataGet2.isDone()).toBe(true);
        expect(seedPhraseMetadataFromMetadataStore).toBeDefined();
        expect(seedPhraseMetadataFromMetadataStore.secretData).not.toBeNull();
        const seedPhrase = seedPhraseMetadataFromMetadataStore.secretData?.[0];
        expect(seedPhrase).toBe(MOCK_SEED_PHRASE);
      });
    });

    it('should throw an error if the user does not have correct password', async () => {
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
        expect(mockAuthSet.isDone()).toBe(false);

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

        const mockMetadataGet = handleMockMetadataGet({
          status: 200,
          body: {
            success: true,
            message: mockToprfEncryptor.encrypt(
              mockToprfEncryptor.keyFromPassword(MOCK_PASSWORD),
              MOCK_SEED_PHRASE,
            ),
          },
        });
        await expect(
          controller.fetchAndRestoreSeedPhraseMetadata(
            verifier,
            verifierID,
            'INCORRECT_PASSWORD',
          ),
        ).rejects.toThrow(SeedlessOnboardingControllerError.IncorrectPassword);
        expect(mockMetadataGet.isDone()).toBe(true);
      });
    });
  });

  describe('vault', () => {
    const MOCK_PASSWORD = 'mock-password';

    it('should create a vault after seedless backup', async () => {
      await withController(async ({ controller, initialState }) => {
        expect(initialState.vault).toBeUndefined();

        const mockAuthGet = handleMockAuthGet();
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

        const mockMetadataSet = handleMockMetadataSet();
        const seedPhraseBackup = await controller.createSeedPhraseBackup({
          verifier,
          verifierID,
          seedPhrase: MOCK_SEED_PHRASE,
          password: MOCK_PASSWORD,
        });

        expect(mockMetadataSet.isDone()).toBe(true);
        expect(seedPhraseBackup).toBeDefined();
        expect(seedPhraseBackup.encryptedSeedPhrase).toBeDefined();
        expect(seedPhraseBackup.encryptionKey).toBeDefined();

        expect(controller.state.vault).toBeDefined();
        expect(controller.state.vault).not.toBe(initialState.vault);
      });
    });

    it('should create a vault after fetching and restoring seed phrase metadata', async () => {
      await withController(async ({ controller, initialState }) => {
        const mockToprfEncryptor = createMockToprfEncryptor();
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
        expect(mockAuthSet.isDone()).toBe(false);

        const mockMetadataGet = handleMockMetadataGet({
          status: 200,
          body: {
            success: true,
            message: mockToprfEncryptor.encrypt(
              mockToprfEncryptor.keyFromPassword(MOCK_PASSWORD),
              MOCK_SEED_PHRASE,
            ),
          },
        });
        await controller.fetchAndRestoreSeedPhraseMetadata(
          verifier,
          verifierID,
          MOCK_PASSWORD,
        );

        expect(mockMetadataGet.isDone()).toBe(true);
        expect(controller.state.vault).toBeDefined();
        expect(controller.state.vault).not.toBe(initialState.vault);
      });
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
        expect(mockAuthSet.isDone()).toBe(false);

        const mockMetadataGet = handleMockMetadataGet({
          status: 200,
          body: {
            success: true,
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

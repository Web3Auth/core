import { EncryptorDecryptor } from './encryption';
import type { SeedlessOnboardingControllerMessenger } from './SeedlessOnboardingController';
import { SeedlessOnboardingController } from './SeedlessOnboardingController';
import MockVaultEncryptor from '../tests/mocks/testEncryptor';

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

describe('SeedlessOnboardingController', () => {
  const MOCK_SEED_PHRASE =
    'horror pink muffin canal young photo magnet runway start elder patch until';

  describe('constructor', () => {
    it('should be able to instantiate', () => {
      const messenger = buildSeedlessOnboardingControllerMessenger();
      const controller = new SeedlessOnboardingController({
        messenger,
      });
      expect(controller).toBeDefined();
      expect(controller.state).toStrictEqual({});
    });

    it('should be able to instantiate with an encryptor', () => {
      const messenger = buildSeedlessOnboardingControllerMessenger();
      const encryptor = new MockVaultEncryptor();

      expect(
        () =>
          new SeedlessOnboardingController({
            messenger,
            encryptor,
          }),
      ).not.toThrow();
    });
  });

  // TODO: add tests for cases where the threshold check fails
  describe('authenticate', () => {
    const encryptor = new MockVaultEncryptor();
    const messenger = buildSeedlessOnboardingControllerMessenger();
    const controller = new SeedlessOnboardingController({
      messenger,
      encryptor,
    });

    it('should be able to register a new user', async () => {
      const authResult = await controller.authenticateOAuthUser({
        idTokens: ['idToken'],
        verifier: 'google',
        verifierID: 'test-user',
        endpoints: ['https://example.com'],
        indexes: [1],
      });

      expect(authResult).toBeDefined();
      expect(authResult.nodeAuthTokens).toBeDefined();
      expect(authResult.hasValidEncKey).toBe(false);
    });

    it('should be able to authenticate an existing user', async () => {
      const authResult = await controller.authenticateOAuthUser({
        idTokens: ['idToken'],
        verifier: 'google',
        verifierID: 'test-user',
        endpoints: ['https://example.com'],
        indexes: [1],
      });

      expect(authResult).toBeDefined();
      expect(authResult.nodeAuthTokens).toBeDefined();
      expect(authResult.hasValidEncKey).toBe(true);
    });
  });

  describe('createSeedPhraseBackup', () => {
    const messenger = buildSeedlessOnboardingControllerMessenger();
    const controller = new SeedlessOnboardingController({
      messenger,
      encryptor: new MockVaultEncryptor(),
    });
    const MOCK_PASSWORD = 'mock-password';

    it('should be able to create a seed phrase backup', async () => {
      await controller.authenticateOAuthUser({
        idTokens: ['idToken'],
        verifier: 'google',
        verifierID: 'test-user',
        endpoints: ['https://example.com'],
        indexes: [1],
      });

      const seedPhraseBackup = await controller.createSeedPhraseBackup({
        seedPhrase: MOCK_SEED_PHRASE,
        password: MOCK_PASSWORD,
      });

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

  describe('restoreAndLoginWithSeedPhrase', () => {
    const messenger = buildSeedlessOnboardingControllerMessenger();
    const controller = new SeedlessOnboardingController({
      messenger,
      encryptor: new MockVaultEncryptor(),
    });
    const MOCK_PASSWORD = 'mock-password';

    it('should be able to restore and login with a seed phrase from metadata', async () => {
      await controller.authenticateOAuthUser({
        idTokens: ['idToken'],
        verifier: 'google',
        verifierID: 'test-user',
        endpoints: ['https://example.com'],
        indexes: [1],
      });

      await controller.createSeedPhraseBackup({
        seedPhrase: MOCK_SEED_PHRASE,
        password: MOCK_PASSWORD,
      });

      const seedPhraseMetadata =
        await controller.fetchAndRestoreSeedPhraseMetadata(MOCK_PASSWORD);

      expect(seedPhraseMetadata).toBeDefined();
      expect(seedPhraseMetadata.secretData).toBeDefined();
      expect(seedPhraseMetadata.secretData?.[0]).toBe(MOCK_SEED_PHRASE);
    });

    it('should be able to create a seed phrase metadata if it does not exist during login', async () => {
      await controller.authenticateOAuthUser({
        idTokens: ['idToken'],
        verifier: 'apple',
        verifierID: 'test-user-2',
        endpoints: ['https://example.com'],
        indexes: [1],
      });

      let seedPhraseMetadataFromMetadataStore =
        await controller.fetchAndRestoreSeedPhraseMetadata(MOCK_PASSWORD);

      expect(seedPhraseMetadataFromMetadataStore).toBeDefined();
      expect(seedPhraseMetadataFromMetadataStore.secretData).toBeNull();

      await controller.createSeedPhraseBackup({
        seedPhrase: MOCK_SEED_PHRASE,
        password: MOCK_PASSWORD,
      });

      seedPhraseMetadataFromMetadataStore =
        await controller.fetchAndRestoreSeedPhraseMetadata(MOCK_PASSWORD);

      expect(seedPhraseMetadataFromMetadataStore).toBeDefined();
      expect(seedPhraseMetadataFromMetadataStore.secretData).not.toBeNull();
      const seedPhrase = seedPhraseMetadataFromMetadataStore.secretData?.[0];
      expect(seedPhrase).toBe(MOCK_SEED_PHRASE);
    });
  });
});

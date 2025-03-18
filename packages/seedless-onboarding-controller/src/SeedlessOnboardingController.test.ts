import type { SeedlessOnboardingControllerMessenger } from './SeedlessOnboardingController';
import { SeedlessOnboardingController } from './SeedlessOnboardingController';
import TestEncryptor from '../tests/mocks/testEncryptor';

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
  describe('constructor', () => {
    it('should be able to instantiate', () => {
      const messenger = buildSeedlessOnboardingControllerMessenger();
      const controller = new SeedlessOnboardingController({
        messenger,
      });
      expect(controller).toBeDefined();
      expect(controller.state).toStrictEqual({});

      // should subscribe to keyring state change during instantiation
      expect(messenger.subscribe).toHaveBeenCalledWith(
        'KeyringController:stateChange',
        expect.any(Function),
      );
    });

    it('should be able to instantiate with an encryptor', () => {
      const messenger = buildSeedlessOnboardingControllerMessenger();
      const encryptor = new TestEncryptor();

      expect(
        () =>
          new SeedlessOnboardingController({
            messenger,
            encryptor,
          }),
      ).not.toThrow();
    });
  });

  describe('backup', () => {
    it('should be able to backup seed phrase', async () => {
      const messenger = buildSeedlessOnboardingControllerMessenger();
      const encryptor = new TestEncryptor();

      const MOCK_SEED_PHRASE = 'MOCK_SEED_PHRASE';
      const MOCK_ENC_KEY = await encryptor.keyFromPassword(
        'MOCK_PASSWORD',
        'MOCK_SALT',
        false,
      );

      const controller = new SeedlessOnboardingController({
        messenger,
        encryptor,
      });

      const createEncKeySpy = jest
        .spyOn(controller, 'createEncryptionKey')
        .mockResolvedValue(MOCK_ENC_KEY);

      const encryptedSeedPhrase = await controller.backupSeedPhrase({
        idToken: 'MOCK_ID_TOKEN',
        verifier: 'google',
        verifierId: 'MOCK_VERIFIER_ID',
        password: 'MOCK_PASSWORD',
        seedPhrase: MOCK_SEED_PHRASE,
      });

      expect(createEncKeySpy).toHaveBeenCalled();
      expect(encryptedSeedPhrase).toBeDefined();

      const decryptedSeedPhrase = await encryptor.decryptWithKey(
        MOCK_ENC_KEY,
        JSON.parse(encryptedSeedPhrase),
      );

      expect(decryptedSeedPhrase).toBe(MOCK_SEED_PHRASE);
    });
  });

  describe('restore', () => {
    it('should not be able to restore seed phrase without correct password', async () => {
      const messenger = buildSeedlessOnboardingControllerMessenger();
      const encryptor = new TestEncryptor();

      const MOCK_SEED_PHRASE = 'MOCK_SEED_PHRASE';
      const MOCK_PASSWORD = 'MOCK_PASSWORD';
      const MOCK_WRONG_PASSWORD = 'MOCK_WRONG_PASSWORD';

      const controller = new SeedlessOnboardingController({
        messenger,
        encryptor,
      });

      const encryptedSeedPhrase = await controller.backupSeedPhrase({
        idToken: 'MOCK_ID_TOKEN',
        verifier: 'google',
        verifierId: 'MOCK_VERIFIER_ID',
        password: MOCK_PASSWORD,
        seedPhrase: MOCK_SEED_PHRASE,
      });

      const fetchEncryptedSRPSpy = jest
        .spyOn(controller, 'fetchEncryptedSRP')
        .mockResolvedValue(encryptedSeedPhrase);

      await expect(() => {
        return controller.restoreSRP({
          idToken: 'MOCK_ID_TOKEN',
          verifier: 'google',
          verifierId: 'MOCK_VERIFIER_ID',
          password: MOCK_WRONG_PASSWORD,
        });
      }).rejects.toThrow('Failed to decrypt');

      expect(fetchEncryptedSRPSpy).toHaveBeenCalled();
    });

    it('should be able to restore seed phrase with correct password', async () => {
      const messenger = buildSeedlessOnboardingControllerMessenger();
      const encryptor = new TestEncryptor();

      const MOCK_SEED_PHRASE = 'MOCK_SEED_PHRASE';
      const MOCK_PASSWORD = 'MOCK_PASSWORD';

      const controller = new SeedlessOnboardingController({
        messenger,
        encryptor,
      });

      const encryptedSeedPhrase = await controller.backupSeedPhrase({
        idToken: 'MOCK_ID_TOKEN',
        verifier: 'google',
        verifierId: 'MOCK_VERIFIER_ID',
        password: MOCK_PASSWORD,
        seedPhrase: MOCK_SEED_PHRASE,
      });

      const fetchEncryptedSRPSpy = jest
        .spyOn(controller, 'fetchEncryptedSRP')
        .mockResolvedValue(encryptedSeedPhrase);

      const restoredSeedPhrase = await controller.restoreSRP({
        idToken: 'MOCK_ID_TOKEN',
        verifier: 'google',
        verifierId: 'MOCK_VERIFIER_ID',
        password: MOCK_PASSWORD,
      });

      expect(fetchEncryptedSRPSpy).toHaveBeenCalled();
      expect(restoredSeedPhrase).toBe(MOCK_SEED_PHRASE);
    });
  });
});

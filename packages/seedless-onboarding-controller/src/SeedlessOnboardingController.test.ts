import type { SeedlessOnboardingControllerMessenger } from './SeedlessOnboardingController';
import { SeedlessOnboardingController } from './SeedlessOnboardingController';

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
});

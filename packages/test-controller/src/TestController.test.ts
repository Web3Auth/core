import type { TestControllerMessenger } from './TestController';
import { TestController } from './TestController';

const testStateMock = {
  state: {
    first: 1,
    second: 2,
  },
};

/**
 * Creates a mock test controller messenger.
 * @returns The mock test controller messenger.
 */
function createMessengerMock() {
  return {
    call: jest.fn(),
    publish: jest.fn(),
    registerActionHandler: jest.fn(),
    registerInitialEventPayload: jest.fn(),
  } as unknown as jest.Mocked<TestControllerMessenger>;
}

describe('TestController', () => {
  const messenger = createMessengerMock();

  describe('constructor', () => {
    it('should create a new TestController', () => {
      const controller = new TestController({
        messenger,
        state: testStateMock,
      });

      const controllerState = controller.state;
      console.log('controllerState', controllerState);
      expect(controllerState).toStrictEqual(testStateMock);
    });
  });
});

import type { RestrictedMessenger } from '@metamask/base-controller';
import { BaseController } from '@metamask/base-controller';

const controllerName = 'UserOperationController';
const stateMetadata = {
  state: { persist: true, anonymous: false },
};
const getDefaultState = () => ({
  state: {},
});

export type TestControllerState = {
  state: Record<string, number>;
};

export type TestControllerActions = {
  type: `${typeof controllerName}:testAction`;
  handler: () => void;
};

export type TestControllerEvents = {
  type: `${typeof controllerName}:testEvent`;
  payload: [string];
};

export type TestControllerMessenger = RestrictedMessenger<
  typeof controllerName,
  TestControllerActions,
  TestControllerEvents,
  TestControllerActions['type'],
  TestControllerEvents['type']
>;

export class TestController extends BaseController<
  typeof controllerName,
  TestControllerState,
  TestControllerMessenger
> {
  constructor({
    messenger,
    state,
  }: {
    messenger: TestControllerMessenger;
    state: Partial<TestControllerState>;
  }) {
    super({
      name: controllerName,
      metadata: stateMetadata,
      messenger,
      state: { ...getDefaultState(), ...state },
    });
  }
}

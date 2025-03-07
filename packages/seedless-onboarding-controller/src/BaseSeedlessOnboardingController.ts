import type {
  RestrictedMessenger,
  StateMetadata,
} from '@metamask/base-controller';
import { BaseController } from '@metamask/base-controller';

const controllerName = 'BaseSeedlessOnboardingController';

// State
// eslint-disable-next-line @typescript-eslint/no-empty-object-type
export type BaseSeedlessOnboardingControllerState = {};

export const defaultState: BaseSeedlessOnboardingControllerState = {};

const metadata: StateMetadata<BaseSeedlessOnboardingControllerState> = {};

// Messenger
export type BaseSeedlessOnboardingControllerMessenger = RestrictedMessenger<
  typeof controllerName,
  never,
  never,
  never,
  never
>;

export default abstract class BaseSeedlessOnboardingController extends BaseController<
  typeof controllerName,
  BaseSeedlessOnboardingControllerState,
  BaseSeedlessOnboardingControllerMessenger
> {
  constructor({
    messenger,
  }: {
    messenger: BaseSeedlessOnboardingControllerMessenger;
  }) {
    super({
      messenger,
      metadata,
      name: controllerName,
      state: { ...defaultState },
    });
  }

  // handle social login directly without using w3a
  // return idToken
  abstract startSocialAuth(params: {
    loginProvider: 'google' | 'apple';
  }): Promise<string>;

  async handleGoogleLogin(): Promise<string> {
    // universal google login, can be reused between web / android / ios (react native)
    return '';
  }

  async generateAndBackupSRP(
    _idToken: string,
    _password: string,
  ): Promise<void> {
    // handle OPRF and generate EK
    // communicate with KeyringController to generate/fetch SRP
    // encrypt SRP with EK and store on metadata service
  }

  async restoreSRP(_idToken: string, _password: string): Promise<void> {
    // handle OPRF and restore EK
    // fetch SRP from metadata service using EK
  }
}

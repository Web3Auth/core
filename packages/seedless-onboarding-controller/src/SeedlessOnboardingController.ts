import type {
  ControllerGetStateAction,
  RestrictedMessenger,
  StateMetadata,
} from '@metamask/base-controller';
import { BaseController } from '@metamask/base-controller';
import type {
  KeyringControllerState,
  KeyringControllerStateChangeEvent,
} from '@metamask/keyring-controller';

import type {
  CreateSeedlessBackupParams,
  OAuthParams,
  RestoreSeedlessBackupParams,
} from './types';

const controllerName = 'BaseSeedlessOnboardingController';

// State
// eslint-disable-next-line @typescript-eslint/no-empty-object-type
export type SeedlessOnboardingControllerState = {};

// Actions
export type SeedlessOnboardingControllerGetStateActions =
  ControllerGetStateAction<
    typeof controllerName,
    SeedlessOnboardingControllerState
  >;

export type AllowedEvents = KeyringControllerStateChangeEvent;
export type AllowedActions = SeedlessOnboardingControllerGetStateActions;

export const defaultState: SeedlessOnboardingControllerState = {};
const metadata: StateMetadata<SeedlessOnboardingControllerState> = {};

// Messenger
export type SeedlessOnboardingControllerMessenger = RestrictedMessenger<
  typeof controllerName,
  AllowedActions,
  AllowedEvents,
  AllowedActions['type'],
  AllowedEvents['type']
>;

export class SeedlessOnboardingController extends BaseController<
  typeof controllerName,
  SeedlessOnboardingControllerState,
  SeedlessOnboardingControllerMessenger
> {
  constructor({
    messenger,
  }: {
    messenger: SeedlessOnboardingControllerMessenger;
  }) {
    super({
      messenger,
      metadata,
      name: controllerName,
      state: { ...defaultState },
    });

    this.#subscribeToMessageEvents();
  }

  async generateAndBackupSRP({
    idToken,
    verifier,
    verifierId,
    password,
    seedPhrase,
  }: CreateSeedlessBackupParams): Promise<void> {
    // handle OPRF and generate EK -> signing key pair
    const ek = this.deriveEk({ idToken, verifier, verifierId, password });
    // encrypt SRP with EK and store on metadata service
    const encryptedSRP = this.#encryptSRP({ seedPhrase, ek });
    // store encryptedSRP on metadata service
    await this.#storeEncryptedSRP({
      idToken,
      verifier,
      verifierId,
      encryptedSRP,
    });
  }

  async restoreSRP({
    idToken,
    password,
    verifier,
    verifierId,
  }: RestoreSeedlessBackupParams): Promise<string> {
    // fetch encrypted SRP from metadata service using EK
    const encryptedSRP = await this.#fetchEncryptedSRP({
      idToken,
      verifier,
      verifierId,
    });
    // handle OPRF and restore EK
    const ek = this.deriveEk({ idToken, verifier, verifierId, password });
    // decrypt SRP
    const srp = this.#decryptSRP({ encryptedSRP, ek });
    return srp;
  }

  private deriveEk(_params: {
    idToken: string;
    verifier: string;
    verifierId: string;
    password: string;
  }): string {
    // derive EK from password and idToken
    // import shares to nodes
    // return EK
    return '';
  }

  #encryptSRP(_params: { seedPhrase: string; ek: string }): string {
    // encrypt SRP with EK
    // return encrypted SRP
    return '';
  }

  #decryptSRP(_params: { encryptedSRP: string; ek: string }): string {
    // decrypt SRP with EK
    // return SRP
    return '';
  }

  async #storeEncryptedSRP(_params: {
    idToken: string;
    verifier: string;
    verifierId: string;
    encryptedSRP: string;
  }) {
    // store encrypted SRP on metadata service
  }

  async #fetchEncryptedSRP(_params: OAuthParams): Promise<string> {
    // fetch encrypted SRP from metadata service
    return '';
  }

  #handleKeyringStateChange(_keyringState: KeyringControllerState) {
    // handle keyring state change
    // Actions to perform when keyring state changes
    // 1. when the existing keyring is removed,
    // 2. when the new keyring is added
    // 3. when more than one keyring is added
  }

  /**
   * Constructor helper for subscribing to message events.
   */
  #subscribeToMessageEvents() {
    this.messagingSystem.subscribe(
      'KeyringController:stateChange',
      (keyringState) => this.#handleKeyringStateChange(keyringState),
    );
  }
}

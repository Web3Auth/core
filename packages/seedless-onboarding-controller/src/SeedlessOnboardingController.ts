import type {
  RestrictedMessenger,
  StateMetadata,
} from '@metamask/base-controller';
import { BaseController } from '@metamask/base-controller';

const controllerName = 'BaseSeedlessOnboardingController';

// State
// eslint-disable-next-line @typescript-eslint/no-empty-object-type
export type SeedlessOnboardingControllerState = {};

export const defaultState: SeedlessOnboardingControllerState = {};

const metadata: StateMetadata<SeedlessOnboardingControllerState> = {};

// Messenger
export type SeedlessOnboardingControllerMessenger = RestrictedMessenger<
  typeof controllerName,
  never,
  never,
  never,
  never
>;

export default class SeedlessOnboardingController extends BaseController<
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
  }

  async verifyIdToken(_params: {
    idToken: string;
    verifier: string;
  }): Promise<void> {
    // verify idToken
    // return user info
  }

  async generateAndBackupSRP({
    idToken,
    verifier,
    verifierId,
    password,
    srp,
  }: {
    srp: string;
    idToken: string;
    verifier: string;
    verifierId: string;
    password: string;
  }): Promise<void> {
    // verify idToken
    await this.verifyIdToken({ idToken, verifier });
    // handle OPRF and generate EK -> signing key pair
    const ek = this.deriveEk({ idToken, verifier, verifierId, password });
    // encrypt SRP with EK and store on metadata service
    const encryptedSRP = this.encryptSRP({ srp, ek });
    // store encryptedSRP on metadata service
    await this.storeEncryptedSRP({
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
  }: {
    idToken: string;
    verifier: string;
    verifierId: string;
    password: string;
  }): Promise<string> {
    // verify idToken
    await this.verifyIdToken({ idToken, verifier });
    // fetch encrypted SRP from metadata service using EK
    const encryptedSRP = await this.fetchEncryptedSRP({
      idToken,
      verifier,
      verifierId,
    });
    // handle OPRF and restore EK
    const ek = this.deriveEk({ idToken, verifier, verifierId, password });
    // decrypt SRP
    const srp = this.decryptSRP({ encryptedSRP, ek });
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

  private encryptSRP(_params: { srp: string; ek: string }): string {
    // encrypt SRP with EK
    // return encrypted SRP
    return '';
  }

  private decryptSRP(_params: { encryptedSRP: string; ek: string }): string {
    // decrypt SRP with EK
    // return SRP
    return '';
  }

  private async storeEncryptedSRP(_params: {
    idToken: string;
    verifier: string;
    verifierId: string;
    encryptedSRP: string;
  }) {
    // store encrypted SRP on metadata service
  }

  private async fetchEncryptedSRP(_params: {
    idToken: string;
    verifier: string;
    verifierId: string;
  }): Promise<string> {
    // fetch encrypted SRP from metadata service
    return '';
  }
}

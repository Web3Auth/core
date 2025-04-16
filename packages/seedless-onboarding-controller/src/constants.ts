import type { RateLimitErrorData } from '@metamask/toprf-secure-backup';

export const controllerName = 'SeedlessOnboardingController';

export enum Web3AuthNetwork {
  Mainnet = 'sapphire_mainnet',
  Devnet = 'sapphire_devnet',
}

export enum SeedlessOnboardingControllerError {
  AuthenticationError = `${controllerName} - Authentication error`,
  TooManyLoginAttempts = `${controllerName} - Too many login attempts`,
  FailedToPersistOprfKey = `${controllerName} - Failed to persist OPRF key`,
  LoginFailedError = `${controllerName} - Login failed`,
  NoOAuthIdToken = `${controllerName} - No OAuth idToken found`,
  InvalidEmptyPassword = `${controllerName} - Password cannot be empty.`,
  WrongPasswordType = `${controllerName} - Password must be of type string.`,
  InvalidVaultData = `${controllerName} - Invalid vault data`,
  VaultDataError = `${controllerName} - The decrypted vault has an unexpected shape.`,
  VaultError = `${controllerName} - Cannot unlock without a previous vault.`,
  InvalidSeedPhraseMetadata = `${controllerName} - Invalid seed phrase metadata`,
}

export class RateLimitError extends Error {
  meta: RateLimitErrorData;

  constructor(message: string, meta: RateLimitErrorData) {
    super(message);
    this.meta = meta;
  }
}

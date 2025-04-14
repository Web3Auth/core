export const controllerName = 'SeedlessOnboardingController';

export enum SeedlessOnboardingControllerError {
  AuthenticationError = `${controllerName} - Authentication error`,
  NoOAuthIdToken = `${controllerName} - No OAuth idToken found`,
  InvalidEmptyPassword = `${controllerName} - Password cannot be empty.`,
  WrongPasswordType = `${controllerName} - Password must be of type string.`,
  InvalidVaultData = `${controllerName} - Invalid vault data`,
  VaultDataError = `${controllerName} - The decrypted vault has an unexpected shape.`,
  VaultError = `${controllerName} - Cannot unlock without a previous vault.`,
  InvalidSeedPhraseMetadata = `${controllerName} - Invalid seed phrase metadata`,
}

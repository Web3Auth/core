export enum SeedlessOnboardingControllerError {
  AuthenticationError = 'SeedlessOnboardingController - Authentication error',
  NoOAuthIdToken = 'SeedlessOnboardingController - No OAuth idToken found',
  InvalidEmptyPassword = 'SeedlessOnboardingController - Password cannot be empty.',
  WrongPasswordType = 'SeedlessOnboardingController - Password must be of type string.',
  VaultDataError = 'KeyringController - The decrypted vault has an unexpected shape.',
  VaultError = 'SeedlessOnboardingController - Cannot unlock without a previous vault.',
  MissingVaultData = 'SeedlessOnboardingController - Cannot persist vault without vault information',
  MissingCredentials = 'SeedlessOnboardingController - Cannot persist vault without password',
  InvalidSeedPhraseMetadata = 'SeedlessOnboardingController - Invalid seed phrase metadata',
}

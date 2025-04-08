export var SeedlessOnboardingControllerError;
(function (SeedlessOnboardingControllerError) {
    SeedlessOnboardingControllerError["NoOAuthIdToken"] = "SeedlessOnboardingController - No OAuth idToken found";
    SeedlessOnboardingControllerError["IncorrectPassword"] = "SeedlessOnboardingController - Incorrect password";
    SeedlessOnboardingControllerError["InvalidEmptyPassword"] = "SeedlessOnboardingController - Password cannot be empty.";
    SeedlessOnboardingControllerError["WrongPasswordType"] = "SeedlessOnboardingController - Password must be of type string.";
    SeedlessOnboardingControllerError["VaultDataError"] = "KeyringController - The decrypted vault has an unexpected shape.";
    SeedlessOnboardingControllerError["VaultError"] = "SeedlessOnboardingController - Cannot unlock without a previous vault.";
    SeedlessOnboardingControllerError["MissingVaultData"] = "SeedlessOnboardingController - Cannot persist vault without vault information";
    SeedlessOnboardingControllerError["MissingCredentials"] = "SeedlessOnboardingController - Cannot persist vault without password";
})(SeedlessOnboardingControllerError || (SeedlessOnboardingControllerError = {}));
//# sourceMappingURL=constants.mjs.map
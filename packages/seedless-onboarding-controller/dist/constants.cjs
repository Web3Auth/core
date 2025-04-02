"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SeedlessOnboardingControllerError = void 0;
var SeedlessOnboardingControllerError;
(function (SeedlessOnboardingControllerError) {
    SeedlessOnboardingControllerError["NoOAuthIdToken"] = "SeedlessOnboardingController - No OAuth idToken found";
    SeedlessOnboardingControllerError["IncorrectPassword"] = "SeedlessOnboardingController - Incorrect password";
    SeedlessOnboardingControllerError["InvalidEmptyPassword"] = "SeedlessOnboardingController - Password cannot be empty.";
    SeedlessOnboardingControllerError["WrongPasswordType"] = "SeedlessOnboardingController - Password must be of type string.";
    SeedlessOnboardingControllerError["MissingVaultData"] = "SeedlessOnboardingController - Cannot persist vault without vault information";
    SeedlessOnboardingControllerError["MissingCredentials"] = "SeedlessOnboardingController - Cannot persist vault without password";
})(SeedlessOnboardingControllerError || (exports.SeedlessOnboardingControllerError = SeedlessOnboardingControllerError = {}));
//# sourceMappingURL=constants.cjs.map
import type { ControllerGetStateAction, ControllerStateChangeEvent, RestrictedMessenger } from "@metamask/base-controller";
import { BaseController } from "@metamask/base-controller";
import type { KeyringControllerStateChangeEvent } from "@metamask/keyring-controller";
import { ToprfAuthClient } from "./ToprfClient.mjs";
import type { AuthenticateUserParams, CreateSeedlessBackupParams, Encryptor, NodeAuthTokens, OAuthVerifier, UpdatePasswordParams } from "./types.mjs";
declare const controllerName = "SeedlessOnboardingController";
export type SeedlessOnboardingControllerState = {
    /**
     * Encrypted array of serialized keyrings data.
     */
    vault?: string;
    /**
     * The node auth tokens from OAuth User authentication after the Social login.
     *
     * This values are used to authenticate users when they go through the Seedless Onboarding flow.
     */
    nodeAuthTokens?: NodeAuthTokens;
    /**
     * Indicates whether the user has already fully/partially completed the Seedless Onboarding flow.
     *
     * An encryption key is generated from user entered password using Threshold OPRF and the seed phrase is encrypted with the key.
     * During the Seedless Onboarding Authentication step, TOPRF services check whether user has already generated the encryption key.
     *
     * If this value is `true`, we can assume that user already has completed the `SeedPhrase` generation step, and user will have to
     * fetch the `SeedPhrase` with correct password. Otherwise, users will be asked to set up seedphrase and password, first.
     */
    hasValidEncryptionKey?: boolean;
};
export type SeedlessOnboardingControllerGetStateActions = ControllerGetStateAction<typeof controllerName, SeedlessOnboardingControllerState>;
export type AllowedActions = SeedlessOnboardingControllerGetStateActions;
export type SeedlessOnboardingControllerStateChangeEvent = ControllerStateChangeEvent<typeof controllerName, SeedlessOnboardingControllerState>;
export type AllowedEvents = KeyringControllerStateChangeEvent | SeedlessOnboardingControllerStateChangeEvent;
export type SeedlessOnboardingControllerMessenger = RestrictedMessenger<typeof controllerName, AllowedActions, AllowedEvents, AllowedActions['type'], AllowedEvents['type']>;
export type SeedlessOnboardingControllerOptions = {
    messenger: SeedlessOnboardingControllerMessenger;
    /**
     * @description Initial state to set on this controller.
     */
    state?: SeedlessOnboardingControllerState;
    /**
     * @description Encryptor used for encryption and decryption of data.
     * @default WebCryptoAPI
     */
    encryptor?: Encryptor;
};
export declare const defaultState: SeedlessOnboardingControllerState;
export declare class SeedlessOnboardingController extends BaseController<typeof controllerName, SeedlessOnboardingControllerState, SeedlessOnboardingControllerMessenger> {
    #private;
    readonly toprfAuthClient: ToprfAuthClient;
    constructor({ messenger, encryptor, state, }: SeedlessOnboardingControllerOptions);
    /**
     * @description Authenticate OAuth user using the seedless onboarding flow
     * and determine if the user is already registered or not.
     * @param params - The parameters for authenticate OAuth user.
     * @param params.idToken - The ID token from Social login
     * @param params.verifier - OAuth verifier
     * @param params.verifierId - user email or id from Social login
     * @returns A promise that resolves to the authentication result.
     */
    authenticateOAuthUser(params: AuthenticateUserParams): Promise<import("./ToprfClient.mjs").AuthenticationResult>;
    /**
     * @description Backup seed phrase using the seedless onboarding flow.
     * @param params - The parameters for backup seed phrase.
     * @param params.verifier - The login provider of the user.
     * @param params.verifierID - The deterministic identifier of the user from the login provider.
     * @param params.password - The password used to create new wallet and seedphrase
     * @param params.seedPhrase - The seed phrase to backup
     * @returns A promise that resolves to the encrypted seed phrase and the encryption key.
     */
    createSeedPhraseBackup({ verifier, verifierID, password, seedPhrase, }: CreateSeedlessBackupParams): Promise<void>;
    /**
     * @description Fetch seed phrase metadata from the metadata store.
     * @param verifier - The login provider of the user.
     * @param verifierID - The deterministic identifier of the user from the login provider.
     * @param password - The password used to create new wallet and seedphrase
     * @returns A promise that resolves to the seed phrase metadata.
     */
    fetchAndRestoreSeedPhraseMetadata(verifier: OAuthVerifier, verifierID: string, password: string): Promise<Uint8Array[]>;
    /**
     * @description Update the password of the seedless onboarding flow.
     *
     * Changing password will also update the encryption key and metadata store with new encrypted values.
     *
     * @param params - The parameters for updating the password.
     * @param params.verifierID - The deterministic identifier of the user from the login provider.
     * @param params.verifier - The login provider of the user.
     * @param params.newPassword - The new password to update.
     * @param params.oldPassword - The old password to verify.
     */
    updatePassword(params: UpdatePasswordParams): Promise<void>;
}
export {};
//# sourceMappingURL=SeedlessOnboardingController.d.mts.map
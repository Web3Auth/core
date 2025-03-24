import type { ControllerGetStateAction, RestrictedMessenger } from "@metamask/base-controller";
import { BaseController } from "@metamask/base-controller";
import type { KeyringControllerStateChangeEvent } from "@metamask/keyring-controller";
import type { AuthenticateUserParams, CreateSeedlessBackupParams, Encryptor, NodeAuthTokens } from "./types.mjs";
declare const controllerName = "SeedlessOnboardingController";
export type SeedlessOnboardingControllerState = {
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
export type AllowedEvents = KeyringControllerStateChangeEvent;
export type AllowedActions = SeedlessOnboardingControllerGetStateActions;
export declare const defaultState: SeedlessOnboardingControllerState;
export type SeedlessOnboardingControllerMessenger = RestrictedMessenger<typeof controllerName, AllowedActions, AllowedEvents, AllowedActions['type'], AllowedEvents['type']>;
export type SeedlessOnboardingControllerOptions = {
    messenger: SeedlessOnboardingControllerMessenger;
    /**
     * @description Encryptor used for encryption and decryption of data.
     * @default WebCryptoAPI
     */
    encryptor?: Encryptor;
};
export declare class SeedlessOnboardingController extends BaseController<typeof controllerName, SeedlessOnboardingControllerState, SeedlessOnboardingControllerMessenger> {
    #private;
    constructor({ messenger, encryptor }: SeedlessOnboardingControllerOptions);
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
     * @param params.password - The password used to create new wallet and seedphrase
     * @param params.seedPhrase - The seed phrase to backup
     * @returns A promise that resolves to the encrypted seed phrase and the encryption key.
     */
    createSeedPhraseBackup({ password, seedPhrase, }: CreateSeedlessBackupParams): Promise<{
        encryptedSeedPhrase: string;
        encryptionKey: string;
    }>;
    /**
     * @description Fetch seed phrase metadata from the metadata store.
     * @param password - The password used to create new wallet and seedphrase
     * @returns A promise that resolves to the seed phrase metadata.
     */
    fetchAndRestoreSeedPhraseMetadata(password: string): Promise<{
        encryptedSeedPhrase: string[] | null;
        encryptionKey: string;
    }>;
}
export {};
//# sourceMappingURL=SeedlessOnboardingController.d.mts.map
var __classPrivateFieldSet = (this && this.__classPrivateFieldSet) || function (receiver, state, value, kind, f) {
    if (kind === "m") throw new TypeError("Private method is not writable");
    if (kind === "a" && !f) throw new TypeError("Private accessor was defined without a setter");
    if (typeof state === "function" ? receiver !== state || !f : !state.has(receiver)) throw new TypeError("Cannot write private member to an object whose class did not declare it");
    return (kind === "a" ? f.call(receiver, value) : f ? f.value = value : state.set(receiver, value)), value;
};
var __classPrivateFieldGet = (this && this.__classPrivateFieldGet) || function (receiver, state, kind, f) {
    if (kind === "a" && !f) throw new TypeError("Private accessor was defined without a getter");
    if (typeof state === "function" ? receiver !== state || !f : !state.has(receiver)) throw new TypeError("Cannot read private member from an object whose class did not declare it");
    return kind === "m" ? f : kind === "a" ? f.call(receiver) : f ? f.value : state.get(receiver);
};
var _SeedlessOnboardingController_instances, _SeedlessOnboardingController_encryptor, _SeedlessOnboardingController_toprfAuthClient, _SeedlessOnboardingController_getNodeAuthTokens, _SeedlessOnboardingController_handleKeyringStateChange, _SeedlessOnboardingController_subscribeToMessageEvents;
import { BaseController } from "@metamask/base-controller";
import { encryptWithKey, decryptWithKey, keyFromPassword, generateSalt, importKey, exportKey } from "@metamask/browser-passworder";
import { ToprfAuthClient } from "./ToprfClient.mjs";
const controllerName = 'SeedlessOnboardingController';
export const defaultState = {};
const seedlessOnboardingMetadata = {
    nodeAuthTokens: {
        persist: true,
        anonymous: false,
    },
    hasValidEncryptionKey: {
        persist: true,
        anonymous: false,
    },
};
export class SeedlessOnboardingController extends BaseController {
    constructor({ messenger, encryptor }) {
        super({
            messenger,
            metadata: seedlessOnboardingMetadata,
            name: controllerName,
            state: { ...defaultState },
        });
        _SeedlessOnboardingController_instances.add(this);
        _SeedlessOnboardingController_encryptor.set(this, {
            keyFromPassword: (password, salt, exportable, opts) => {
                const randomSalt = salt || Math.random().toString(36).substring(2, 15);
                const exportableKey = exportable ?? true;
                return keyFromPassword(password, randomSalt, exportableKey, opts);
            },
            encryptWithKey,
            decryptWithKey,
            generateSalt,
            importKey,
            exportKey,
        });
        _SeedlessOnboardingController_toprfAuthClient.set(this, void 0);
        if (encryptor) {
            __classPrivateFieldSet(this, _SeedlessOnboardingController_encryptor, encryptor, "f");
        }
        __classPrivateFieldSet(this, _SeedlessOnboardingController_toprfAuthClient, new ToprfAuthClient(__classPrivateFieldGet(this, _SeedlessOnboardingController_encryptor, "f")), "f");
        __classPrivateFieldGet(this, _SeedlessOnboardingController_instances, "m", _SeedlessOnboardingController_subscribeToMessageEvents).call(this);
    }
    /**
     * @description Authenticate OAuth user using the seedless onboarding flow
     * and determine if the user is already registered or not.
     * @param params - The parameters for authenticate OAuth user.
     * @param params.idToken - The ID token from Social login
     * @param params.verifier - OAuth verifier
     * @param params.verifierId - user email or id from Social login
     * @returns A promise that resolves to the authentication result.
     */
    async authenticateOAuthUser(params) {
        const verificationResult = await __classPrivateFieldGet(this, _SeedlessOnboardingController_toprfAuthClient, "f").authenticate(params);
        this.update((state) => {
            state.nodeAuthTokens = verificationResult.nodeAuthTokens;
            state.hasValidEncryptionKey = verificationResult.hasValidEncKey;
        });
        return verificationResult;
    }
    /**
     * @description Backup seed phrase using the seedless onboarding flow.
     * @param params - The parameters for backup seed phrase.
     * @param params.password - The password used to create new wallet and seedphrase
     * @param params.seedPhrase - The seed phrase to backup
     * @returns A promise that resolves to the encrypted seed phrase and the encryption key.
     */
    async createSeedPhraseBackup({ password, seedPhrase, }) {
        const nodeAuthTokens = __classPrivateFieldGet(this, _SeedlessOnboardingController_instances, "m", _SeedlessOnboardingController_getNodeAuthTokens).call(this);
        const { encKey } = await __classPrivateFieldGet(this, _SeedlessOnboardingController_toprfAuthClient, "f").createEncKey({
            nodeAuthTokens,
            password,
        });
        const storeResult = await __classPrivateFieldGet(this, _SeedlessOnboardingController_toprfAuthClient, "f").storeSecretData({
            nodeAuthTokens,
            encKey,
            secretData: seedPhrase,
        });
        return {
            encryptedSeedPhrase: storeResult.encryptedSecretData,
            encryptionKey: storeResult.encKey,
        };
    }
    /**
     * @description Fetch seed phrase metadata from the metadata store.
     * @param password - The password used to create new wallet and seedphrase
     * @returns A promise that resolves to the seed phrase metadata.
     */
    async fetchAndRestoreSeedPhraseMetadata(password) {
        const nodeAuthTokens = __classPrivateFieldGet(this, _SeedlessOnboardingController_instances, "m", _SeedlessOnboardingController_getNodeAuthTokens).call(this);
        const { encKey, secretData } = await __classPrivateFieldGet(this, _SeedlessOnboardingController_toprfAuthClient, "f").fetchSecretData({
            nodeAuthTokens,
            password,
        });
        return {
            encryptedSeedPhrase: secretData,
            encryptionKey: encKey,
        };
    }
}
_SeedlessOnboardingController_encryptor = new WeakMap(), _SeedlessOnboardingController_toprfAuthClient = new WeakMap(), _SeedlessOnboardingController_instances = new WeakSet(), _SeedlessOnboardingController_getNodeAuthTokens = function _SeedlessOnboardingController_getNodeAuthTokens() {
    const { nodeAuthTokens } = this.state;
    if (!nodeAuthTokens) {
        // TODO: create standard errors
        throw new Error('Node auth tokens not found');
    }
    return nodeAuthTokens;
}, _SeedlessOnboardingController_handleKeyringStateChange = function _SeedlessOnboardingController_handleKeyringStateChange(_keyringState) {
    // handle keyring state change
    // Actions to perform when keyring state changes
    // 1. when the existing keyring is removed,
    // 2. when the new keyring is added
    // 3. when more than one keyring is added
}, _SeedlessOnboardingController_subscribeToMessageEvents = function _SeedlessOnboardingController_subscribeToMessageEvents() {
    this.messagingSystem.subscribe('KeyringController:stateChange', (keyringState) => __classPrivateFieldGet(this, _SeedlessOnboardingController_instances, "m", _SeedlessOnboardingController_handleKeyringStateChange).call(this, keyringState));
};
//# sourceMappingURL=SeedlessOnboardingController.mjs.map
"use strict";
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
var _SeedlessOnboardingController_instances, _SeedlessOnboardingController_encryptor, _SeedlessOnboardingController_getNodeAuthTokens;
Object.defineProperty(exports, "__esModule", { value: true });
exports.SeedlessOnboardingController = exports.defaultState = void 0;
const base_controller_1 = require("@metamask/base-controller");
const browser_passworder_1 = require("@metamask/browser-passworder");
const constants_1 = require("./constants.cjs");
const ToprfClient_1 = require("./ToprfClient.cjs");
const controllerName = 'SeedlessOnboardingController';
/**
 * Seedless Onboarding Controller State Metadata.
 *
 * This allows us to choose if fields of the state should be persisted or not
 * using the `persist` flag; and if they can be sent to Sentry or not, using
 * the `anonymous` flag.
 */
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
exports.defaultState = {
    hasValidEncryptionKey: false,
};
class SeedlessOnboardingController extends base_controller_1.BaseController {
    constructor({ messenger, encryptor, state, }) {
        super({
            messenger,
            metadata: seedlessOnboardingMetadata,
            name: controllerName,
            state: { ...state, ...exports.defaultState },
        });
        _SeedlessOnboardingController_instances.add(this);
        _SeedlessOnboardingController_encryptor.set(this, {
            keyFromPassword: (password, salt, exportable, opts) => {
                const randomSalt = salt || Math.random().toString(36).substring(2, 15);
                const exportableKey = exportable ?? true;
                return (0, browser_passworder_1.keyFromPassword)(password, randomSalt, exportableKey, opts);
            },
            encryptWithKey: browser_passworder_1.encryptWithKey,
            decryptWithKey: browser_passworder_1.decryptWithKey,
            generateSalt: browser_passworder_1.generateSalt,
            importKey: browser_passworder_1.importKey,
            exportKey: browser_passworder_1.exportKey,
        });
        if (encryptor) {
            __classPrivateFieldSet(this, _SeedlessOnboardingController_encryptor, encryptor, "f");
        }
        this.toprfAuthClient = new ToprfClient_1.ToprfAuthClient(__classPrivateFieldGet(this, _SeedlessOnboardingController_encryptor, "f"));
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
        const verificationResult = await this.toprfAuthClient.authenticate(params);
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
        const { encKey } = await this.toprfAuthClient.createEncKey({
            nodeAuthTokens,
            password,
        });
        const storeResult = await this.toprfAuthClient.storeSecretData({
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
        try {
            const nodeAuthTokens = __classPrivateFieldGet(this, _SeedlessOnboardingController_instances, "m", _SeedlessOnboardingController_getNodeAuthTokens).call(this);
            const { encKey, secretData } = await this.toprfAuthClient.fetchSecretData({
                nodeAuthTokens,
                password,
            });
            return {
                secretData,
                encryptionKey: encKey,
            };
        }
        catch (error) {
            console.error('[fetchAndRestoreSeedPhraseMetadata] error', error);
            throw new Error(constants_1.SeedlessOnboardingControllerError.IncorrectPassword);
        }
    }
}
exports.SeedlessOnboardingController = SeedlessOnboardingController;
_SeedlessOnboardingController_encryptor = new WeakMap(), _SeedlessOnboardingController_instances = new WeakSet(), _SeedlessOnboardingController_getNodeAuthTokens = function _SeedlessOnboardingController_getNodeAuthTokens() {
    const { nodeAuthTokens } = this.state;
    if (!nodeAuthTokens) {
        throw new Error(constants_1.SeedlessOnboardingControllerError.NoOAuthIdToken);
    }
    return nodeAuthTokens;
};
//# sourceMappingURL=SeedlessOnboardingController.cjs.map
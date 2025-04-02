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
var _SeedlessOnboardingController_instances, _SeedlessOnboardingController_encryptor, _SeedlessOnboardingController_vaultOperationMutex, _SeedlessOnboardingController_getNodeAuthTokens, _SeedlessOnboardingController_createNewVaultWithAuthData, _SeedlessOnboardingController_updateVault, _SeedlessOnboardingController_withVaultLock, _SeedlessOnboardingController_getSerializedVaultData;
Object.defineProperty(exports, "__esModule", { value: true });
exports.SeedlessOnboardingController = exports.defaultState = void 0;
const base_controller_1 = require("@metamask/base-controller");
const browser_passworder_1 = require("@metamask/browser-passworder");
const async_mutex_1 = require("async-mutex");
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
    vault: {
        persist: true,
        anonymous: false,
    },
    hasValidEncryptionKey: {
        persist: true,
        anonymous: false,
    },
    nodeAuthTokens: {
        persist: false,
        anonymous: true,
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
            encrypt: browser_passworder_1.encrypt,
            decrypt: browser_passworder_1.decrypt,
        });
        _SeedlessOnboardingController_vaultOperationMutex.set(this, new async_mutex_1.Mutex());
        if (encryptor) {
            __classPrivateFieldSet(this, _SeedlessOnboardingController_encryptor, encryptor, "f");
        }
        this.toprfAuthClient = new ToprfClient_1.ToprfAuthClient();
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
     * @param params.verifier - The login provider of the user.
     * @param params.verifierID - The deterministic identifier of the user from the login provider.
     * @param params.password - The password used to create new wallet and seedphrase
     * @param params.seedPhrase - The seed phrase to backup
     * @returns A promise that resolves to the encrypted seed phrase and the encryption key.
     */
    async createSeedPhraseBackup({ verifier, verifierID, password, seedPhrase, }) {
        const nodeAuthTokens = __classPrivateFieldGet(this, _SeedlessOnboardingController_instances, "m", _SeedlessOnboardingController_getNodeAuthTokens).call(this);
        const { encKey } = await this.toprfAuthClient.createEncKey({
            nodeAuthTokens,
            password,
            verifier,
            verifierID,
        });
        const storeResult = await this.toprfAuthClient.storeSecretData({
            nodeAuthTokens,
            encKey,
            secretData: seedPhrase,
        });
        await __classPrivateFieldGet(this, _SeedlessOnboardingController_instances, "m", _SeedlessOnboardingController_createNewVaultWithAuthData).call(this, {
            password,
            authTokens: nodeAuthTokens,
            toprfEncryptionKey: storeResult.encKey,
        });
        return {
            encryptedSeedPhrase: storeResult.encryptedSecretData,
            encryptionKey: storeResult.encKey,
        };
    }
    /**
     * @description Fetch seed phrase metadata from the metadata store.
     * @param verifier - The login provider of the user.
     * @param verifierID - The deterministic identifier of the user from the login provider.
     * @param password - The password used to create new wallet and seedphrase
     * @returns A promise that resolves to the seed phrase metadata.
     */
    async fetchAndRestoreSeedPhraseMetadata(verifier, verifierID, password) {
        try {
            const nodeAuthTokens = __classPrivateFieldGet(this, _SeedlessOnboardingController_instances, "m", _SeedlessOnboardingController_getNodeAuthTokens).call(this);
            const { encKey } = await this.toprfAuthClient.createEncKey({
                nodeAuthTokens,
                password,
                verifier,
                verifierID,
            });
            const { secretData } = await this.toprfAuthClient.fetchSecretData({
                nodeAuthTokens,
                encKey,
            });
            if (secretData && secretData.length > 0) {
                await __classPrivateFieldGet(this, _SeedlessOnboardingController_instances, "m", _SeedlessOnboardingController_createNewVaultWithAuthData).call(this, {
                    password,
                    authTokens: nodeAuthTokens,
                    toprfEncryptionKey: encKey,
                });
            }
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
_SeedlessOnboardingController_encryptor = new WeakMap(), _SeedlessOnboardingController_vaultOperationMutex = new WeakMap(), _SeedlessOnboardingController_instances = new WeakSet(), _SeedlessOnboardingController_getNodeAuthTokens = function _SeedlessOnboardingController_getNodeAuthTokens() {
    const { nodeAuthTokens } = this.state;
    if (!nodeAuthTokens) {
        throw new Error(constants_1.SeedlessOnboardingControllerError.NoOAuthIdToken);
    }
    return nodeAuthTokens;
}, _SeedlessOnboardingController_createNewVaultWithAuthData = async function _SeedlessOnboardingController_createNewVaultWithAuthData({ password, authTokens, toprfEncryptionKey, }) {
    await __classPrivateFieldGet(this, _SeedlessOnboardingController_instances, "m", _SeedlessOnboardingController_updateVault).call(this, {
        password,
        vaultData: {
            authTokens,
            toprfEncryptionKey,
        },
    });
}, _SeedlessOnboardingController_updateVault = function _SeedlessOnboardingController_updateVault({ password, vaultData, }) {
    return __classPrivateFieldGet(this, _SeedlessOnboardingController_instances, "m", _SeedlessOnboardingController_withVaultLock).call(this, async () => {
        assertIsValidPassword(password);
        const serializedAuthData = await __classPrivateFieldGet(this, _SeedlessOnboardingController_instances, "m", _SeedlessOnboardingController_getSerializedVaultData).call(this, vaultData);
        const updatedState = {};
        updatedState.vault = await __classPrivateFieldGet(this, _SeedlessOnboardingController_encryptor, "f").encrypt(password, serializedAuthData);
        if (!updatedState.vault) {
            throw new Error(constants_1.SeedlessOnboardingControllerError.MissingVaultData);
        }
        this.update((state) => {
            state.vault = updatedState.vault;
        });
        return true;
    });
}, _SeedlessOnboardingController_withVaultLock = 
/**
 * Lock the vault mutex before executing the given function,
 * and release it after the function is resolved or after an
 * error is thrown.
 *
 * This ensures that each operation that interacts with the vault
 * is executed in a mutually exclusive way.
 *
 * @param callback - The function to execute while the vault mutex is locked.
 * @returns The result of the function.
 */
async function _SeedlessOnboardingController_withVaultLock(callback) {
    return withLock(__classPrivateFieldGet(this, _SeedlessOnboardingController_vaultOperationMutex, "f"), callback);
}, _SeedlessOnboardingController_getSerializedVaultData = async function _SeedlessOnboardingController_getSerializedVaultData(data) {
    return JSON.stringify(data);
};
/**
 * Assert that the provided password is a valid non-empty string.
 *
 * @param password - The password to check.
 * @throws If the password is not a valid string.
 */
function assertIsValidPassword(password) {
    if (typeof password !== 'string') {
        throw new Error(constants_1.SeedlessOnboardingControllerError.WrongPasswordType);
    }
    if (!password || !password.length) {
        throw new Error(constants_1.SeedlessOnboardingControllerError.InvalidEmptyPassword);
    }
}
/**
 * Lock the given mutex before executing the given function,
 * and release it after the function is resolved or after an
 * error is thrown.
 *
 * @param mutex - The mutex to lock.
 * @param callback - The function to execute while the mutex is locked.
 * @returns The result of the function.
 */
async function withLock(mutex, callback) {
    const releaseLock = await mutex.acquire();
    try {
        return await callback({ releaseLock });
    }
    finally {
        releaseLock();
    }
}
//# sourceMappingURL=SeedlessOnboardingController.cjs.map
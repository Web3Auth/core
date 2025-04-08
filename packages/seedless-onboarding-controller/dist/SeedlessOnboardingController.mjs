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
var _SeedlessOnboardingController_instances, _SeedlessOnboardingController_encryptor, _SeedlessOnboardingController_vaultOperationMutex, _SeedlessOnboardingController_getNodeAuthTokens, _SeedlessOnboardingController_unlockVault, _SeedlessOnboardingController_createNewVaultWithAuthData, _SeedlessOnboardingController_updateVault, _SeedlessOnboardingController_withVaultLock, _SeedlessOnboardingController_getSerializedStateData, _SeedlessOnboardingController_serializeKeyData, _SeedlessOnboardingController_parseVaultData;
import { BaseController } from "@metamask/base-controller";
import { encrypt, decrypt } from "@metamask/browser-passworder";
import { utf8ToBytes } from "@noble/ciphers/utils";
import { Mutex } from "async-mutex";
import { SeedlessOnboardingControllerError } from "./constants.mjs";
import { ToprfAuthClient } from "./ToprfClient.mjs";
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
export const defaultState = {
    hasValidEncryptionKey: false,
};
export class SeedlessOnboardingController extends BaseController {
    constructor({ messenger, encryptor, state, }) {
        super({
            messenger,
            metadata: seedlessOnboardingMetadata,
            name: controllerName,
            state: { ...state, ...defaultState },
        });
        _SeedlessOnboardingController_instances.add(this);
        _SeedlessOnboardingController_encryptor.set(this, {
            encrypt,
            decrypt,
        });
        _SeedlessOnboardingController_vaultOperationMutex.set(this, new Mutex());
        if (encryptor) {
            __classPrivateFieldSet(this, _SeedlessOnboardingController_encryptor, encryptor, "f");
        }
        this.toprfAuthClient = new ToprfAuthClient();
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
        const { encKey, authKeyPair } = await this.toprfAuthClient.createEncKey({
            nodeAuthTokens,
            password,
            verifier,
            verifierID,
        });
        const seedPhraseBytes = utf8ToBytes(seedPhrase);
        await this.toprfAuthClient.addSecretDataItem({
            nodeAuthTokens,
            encKey,
            secretData: seedPhraseBytes,
            authKeyPair,
        });
        await __classPrivateFieldGet(this, _SeedlessOnboardingController_instances, "m", _SeedlessOnboardingController_createNewVaultWithAuthData).call(this, {
            password,
            authTokens: nodeAuthTokens,
            rawToprfEncryptionKey: encKey,
            rawToprfAuthKeyPair: authKeyPair,
        });
    }
    /**
     * @description Fetch seed phrase metadata from the metadata store.
     * @param verifier - The login provider of the user.
     * @param verifierID - The deterministic identifier of the user from the login provider.
     * @param password - The password used to create new wallet and seedphrase
     * @returns A promise that resolves to the seed phrase metadata.
     */
    async fetchAndRestoreSeedPhraseMetadata(verifier, verifierID, password) {
        const nodeAuthTokens = __classPrivateFieldGet(this, _SeedlessOnboardingController_instances, "m", _SeedlessOnboardingController_getNodeAuthTokens).call(this);
        const { encKey, authKeyPair } = await this.toprfAuthClient.createEncKey({
            nodeAuthTokens,
            password,
            verifier,
            verifierID,
        });
        const secretData = await this.toprfAuthClient.fetchAllSecretData({
            nodeAuthTokens,
            decKey: encKey,
            authKeyPair,
        });
        if (secretData && secretData.length > 0) {
            await __classPrivateFieldGet(this, _SeedlessOnboardingController_instances, "m", _SeedlessOnboardingController_createNewVaultWithAuthData).call(this, {
                password,
                authTokens: nodeAuthTokens,
                rawToprfEncryptionKey: encKey,
                rawToprfAuthKeyPair: authKeyPair,
            });
        }
        return secretData;
    }
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
    async updatePassword(params) {
        const { verifier, verifierID, newPassword, oldPassword } = params;
        // 1. unlock the encrypted vault with old password, retrieve the ek and authTokens from the vault
        const { nodeAuthTokens, toprfEncryptionKey, toprfAuthKeyPair } = await __classPrivateFieldGet(this, _SeedlessOnboardingController_instances, "m", _SeedlessOnboardingController_unlockVault).call(this, oldPassword);
        // 2. call changePassword method from Toprf Client with old password, new password
        const { encKey: newEncKey, authKeyPair: newAuthKeyPair } = await this.toprfAuthClient.changeEncKey({
            nodeAuthTokens,
            verifier,
            verifierID,
            oldEncKey: toprfEncryptionKey,
            oldAuthKeyPair: toprfAuthKeyPair,
            password: newPassword,
        });
        // 3. update and encrypt the vault with new password
        await __classPrivateFieldGet(this, _SeedlessOnboardingController_instances, "m", _SeedlessOnboardingController_createNewVaultWithAuthData).call(this, {
            password: newPassword,
            authTokens: nodeAuthTokens,
            rawToprfEncryptionKey: newEncKey,
            rawToprfAuthKeyPair: newAuthKeyPair,
        });
    }
}
_SeedlessOnboardingController_encryptor = new WeakMap(), _SeedlessOnboardingController_vaultOperationMutex = new WeakMap(), _SeedlessOnboardingController_instances = new WeakSet(), _SeedlessOnboardingController_getNodeAuthTokens = function _SeedlessOnboardingController_getNodeAuthTokens() {
    const { nodeAuthTokens } = this.state;
    if (!nodeAuthTokens) {
        throw new Error(SeedlessOnboardingControllerError.NoOAuthIdToken);
    }
    return nodeAuthTokens;
}, _SeedlessOnboardingController_unlockVault = async function _SeedlessOnboardingController_unlockVault(password) {
    return __classPrivateFieldGet(this, _SeedlessOnboardingController_instances, "m", _SeedlessOnboardingController_withVaultLock).call(this, async () => {
        assertIsValidPassword(password);
        const encryptedVault = this.state.vault;
        if (!encryptedVault) {
            throw new Error(SeedlessOnboardingControllerError.VaultError);
        }
        const decryptedVaultData = await __classPrivateFieldGet(this, _SeedlessOnboardingController_encryptor, "f").decrypt(password, encryptedVault);
        return __classPrivateFieldGet(this, _SeedlessOnboardingController_instances, "m", _SeedlessOnboardingController_parseVaultData).call(this, decryptedVaultData);
    });
}, _SeedlessOnboardingController_createNewVaultWithAuthData = async function _SeedlessOnboardingController_createNewVaultWithAuthData({ password, authTokens, rawToprfEncryptionKey, rawToprfAuthKeyPair, }) {
    const { toprfEncryptionKey, toprfAuthKeyPair } = await __classPrivateFieldGet(this, _SeedlessOnboardingController_instances, "m", _SeedlessOnboardingController_serializeKeyData).call(this, rawToprfEncryptionKey, rawToprfAuthKeyPair);
    await __classPrivateFieldGet(this, _SeedlessOnboardingController_instances, "m", _SeedlessOnboardingController_updateVault).call(this, {
        password,
        vaultData: {
            authTokens,
            toprfEncryptionKey,
            toprfAuthKeyPair,
        },
    });
}, _SeedlessOnboardingController_updateVault = async function _SeedlessOnboardingController_updateVault({ password, vaultData, }) {
    return __classPrivateFieldGet(this, _SeedlessOnboardingController_instances, "m", _SeedlessOnboardingController_withVaultLock).call(this, async () => {
        assertIsValidPassword(password);
        const serializedStateData = await __classPrivateFieldGet(this, _SeedlessOnboardingController_instances, "m", _SeedlessOnboardingController_getSerializedStateData).call(this, vaultData);
        const updatedState = {};
        updatedState.vault = await __classPrivateFieldGet(this, _SeedlessOnboardingController_encryptor, "f").encrypt(password, serializedStateData);
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
}, _SeedlessOnboardingController_getSerializedStateData = async function _SeedlessOnboardingController_getSerializedStateData(data) {
    return JSON.stringify(data);
}, _SeedlessOnboardingController_serializeKeyData = 
/**
 * @description Serialize the encryption key and authentication key pair.
 * @param encKey - The encryption key to serialize.
 * @param authKeyPair - The authentication key pair to serialize.
 * @returns The serialized encryption key and authentication key pair.
 */
async function _SeedlessOnboardingController_serializeKeyData(encKey, authKeyPair) {
    const b64EncodedEncKey = Buffer.from(encKey).toString('base64');
    const b64EncodedAuthKeyPair = JSON.stringify({
        sk: authKeyPair.sk.toString(),
        pk: Buffer.from(authKeyPair.pk).toString('base64'),
    });
    return {
        toprfEncryptionKey: b64EncodedEncKey,
        toprfAuthKeyPair: b64EncodedAuthKeyPair,
    };
}, _SeedlessOnboardingController_parseVaultData = async function _SeedlessOnboardingController_parseVaultData(data) {
    if (typeof data !== 'string') {
        throw new Error(SeedlessOnboardingControllerError.VaultDataError);
    }
    const parsedVaultData = JSON.parse(data);
    if (!('authTokens' in parsedVaultData) ||
        !('toprfEncryptionKey' in parsedVaultData) ||
        !('toprfAuthKeyPair' in parsedVaultData)) {
        throw new Error(SeedlessOnboardingControllerError.VaultDataError);
    }
    const rawToprfEncryptionKey = new Uint8Array(Buffer.from(parsedVaultData.toprfEncryptionKey, 'base64'));
    const parsedToprfAuthKeyPair = JSON.parse(parsedVaultData.toprfAuthKeyPair);
    const rawToprfAuthKeyPair = {
        sk: BigInt(parsedToprfAuthKeyPair.sk),
        pk: new Uint8Array(Buffer.from(parsedToprfAuthKeyPair.pk, 'base64')),
    };
    return {
        nodeAuthTokens: parsedVaultData.authTokens,
        toprfEncryptionKey: rawToprfEncryptionKey,
        toprfAuthKeyPair: rawToprfAuthKeyPair,
    };
};
/**
 * Assert that the provided password is a valid non-empty string.
 *
 * @param password - The password to check.
 * @throws If the password is not a valid string.
 */
function assertIsValidPassword(password) {
    if (typeof password !== 'string') {
        throw new Error(SeedlessOnboardingControllerError.WrongPasswordType);
    }
    if (!password || !password.length) {
        throw new Error(SeedlessOnboardingControllerError.InvalidEmptyPassword);
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
//# sourceMappingURL=SeedlessOnboardingController.mjs.map
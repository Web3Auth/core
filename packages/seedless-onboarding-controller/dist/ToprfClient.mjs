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
var _ToprfAuthClient_instances, _ToprfAuthClient_mockAuthStore, _ToprfAuthClient_mockMetadataStore, _ToprfAuthClient_encryptor, _ToprfAuthClient_isValidAuthResponse, _ToprfAuthClient_generateMockNodeAuthTokens;
import { bytesToHex } from "@metamask/utils";
import { SeedlessOnboardingControllerError } from "./constants.mjs";
import { EncryptorDecryptor } from "./encryption.mjs";
import { MetadataStore } from "./MetadataStore.mjs";
// TODO: remove the class once the toprf-sdk is ready
// This class is a mock implementation for the toprf-sdk
export class ToprfAuthClient {
    constructor() {
        _ToprfAuthClient_instances.add(this);
        _ToprfAuthClient_mockAuthStore.set(this, new MetadataStore('auth'));
        _ToprfAuthClient_mockMetadataStore.set(this, new MetadataStore('metadata'));
        // TODO: remove this once the toprf-sdk is ready
        // encryptions/signings should be done in the toprf-sdk
        _ToprfAuthClient_encryptor.set(this, void 0);
        __classPrivateFieldSet(this, _ToprfAuthClient_encryptor, new EncryptorDecryptor(), "f");
    }
    /**
     * Mock implementation of the authenticate method
     *
     * @param params - The parameters for the authentication
     * @returns The authentication result
     */
    async authenticate(params) {
        const key = `${params.verifier}:${params.verifierID}`;
        const authenticationResult = await __classPrivateFieldGet(this, _ToprfAuthClient_mockAuthStore, "f").get(key);
        let hasValidEncKey = false;
        let nodeAuthTokens;
        const isValidAuthResponse = __classPrivateFieldGet(this, _ToprfAuthClient_instances, "m", _ToprfAuthClient_isValidAuthResponse).call(this, authenticationResult);
        if (authenticationResult === undefined || !isValidAuthResponse) {
            // generate mock nodeAuthTokens
            nodeAuthTokens = __classPrivateFieldGet(this, _ToprfAuthClient_instances, "m", _ToprfAuthClient_generateMockNodeAuthTokens).call(this, params.verifier, params.verifierID);
            const data = JSON.stringify({
                nodeAuthTokens,
                hasValidEncKey,
            });
            await __classPrivateFieldGet(this, _ToprfAuthClient_mockAuthStore, "f").set(key, data);
        }
        else {
            const parsedAuthenticationResult = JSON.parse(authenticationResult);
            nodeAuthTokens = parsedAuthenticationResult.nodeAuthTokens;
            hasValidEncKey = Boolean(parsedAuthenticationResult.hasValidEncKey);
        }
        return {
            nodeAuthTokens,
            hasValidEncKey,
        };
    }
    /**
     * Mock implementation of the createEncKey method
     * This method derives the encryption key from the password with Threshold OPRF
     *
     * @param params - The parameters for the createEncKey
     * @returns The createEncKey result
     */
    async createEncKey(params) {
        const key = `${params.verifier}:${params.verifierID}`;
        const data = JSON.stringify({
            nodeAuthTokens: params.nodeAuthTokens,
            hasValidEncKey: true,
        });
        await __classPrivateFieldGet(this, _ToprfAuthClient_mockAuthStore, "f").set(key, data);
        const encKey = __classPrivateFieldGet(this, _ToprfAuthClient_encryptor, "f").keyFromPassword(params.password);
        const authKeyPair = __classPrivateFieldGet(this, _ToprfAuthClient_encryptor, "f").authKeyPairFromPassword(params.password);
        return {
            encKey,
            authKeyPair,
        };
    }
    /**
     * This function replaces the existing encryption key with a new one and copies the secret data of existing encryption key to the new one.
     *
     * @param params - The parameters for changing the encryption key.
     * @param params.nodeAuthTokens - The tokens issued by the nodes on authenticating the user.
     * @param params.newPassword - The new password of the user.
     * @param params.keyPair - The current encryption key of the user.
     *
     * @returns A promise that resolves with the new encryption key.
     */
    async changeEncKey(params) {
        try {
            const key = `${params.verifier}:${params.verifierID}`;
            const data = JSON.stringify({
                nodeAuthTokens: params.nodeAuthTokens,
                hasValidEncKey: true,
            });
            await __classPrivateFieldGet(this, _ToprfAuthClient_mockAuthStore, "f").set(key, data);
            const encKey = __classPrivateFieldGet(this, _ToprfAuthClient_encryptor, "f").keyFromPassword(params.password);
            const authKeyPair = __classPrivateFieldGet(this, _ToprfAuthClient_encryptor, "f").authKeyPairFromPassword(params.password);
            return {
                encKey,
                authKeyPair,
            };
        }
        catch (e) {
            throw new Error(SeedlessOnboardingControllerError.IncorrectPassword);
        }
    }
    /**
     * This function encrypts the secret data using the encryption key and stores it nodes metadata store in encrypted form.
     *
     * @param params - The parameters for registering new secret data.
     * @param params.nodeAuthTokens - The tokens issued by the nodes on authenticating the user.
     * @param params.keyPair - The encryption/decryption key pair which is used to encrypt the secret data before storing it.
     * @param params.secretData - The array of secret data to be registered.
     *
     * @returns A promise that resolves if the operation is successful.
     */
    async addSecretDataItem(params) {
        const { encKey, secretData } = params;
        const encryptedSecretData = __classPrivateFieldGet(this, _ToprfAuthClient_encryptor, "f").encrypt(encKey, secretData);
        const pubKey = bytesToHex(params.authKeyPair.pk);
        await __classPrivateFieldGet(this, _ToprfAuthClient_mockMetadataStore, "f").set(pubKey, encryptedSecretData);
    }
    /**
     * This function fetches all secret data items associated with the given
     * auth pub key, decrypts, and returns them.
     *
     * @param params - The parameters for fetching the secret data.
     * @param params.nodeAuthTokens - The tokens issued by the nodes on authenticating the user.
     * @param params.decKey - The decryption key to be used to decrypt the secret data.
     * @param params.authKeyPair - The authentication key to be used to provide valid signature for fetching the secret data.
     *
     * @returns A promise that resolves with the decrypted secret data. Null if no secret data is found.
     */
    async fetchAllSecretData(params) {
        const pubKey = bytesToHex(params.authKeyPair.pk);
        const encryptedSecretData = (await __classPrivateFieldGet(this, _ToprfAuthClient_mockMetadataStore, "f").get(pubKey)) || [];
        const secretData = [];
        try {
            const decryptedSecretData = encryptedSecretData.map((data) => {
                const rawData = new Uint8Array(Buffer.from(data, 'base64'));
                return __classPrivateFieldGet(this, _ToprfAuthClient_encryptor, "f").decrypt(params.decKey, rawData);
            });
            secretData.push(...decryptedSecretData);
        }
        catch (e) {
            throw new Error(SeedlessOnboardingControllerError.IncorrectPassword);
        }
        return secretData;
    }
}
_ToprfAuthClient_mockAuthStore = new WeakMap(), _ToprfAuthClient_mockMetadataStore = new WeakMap(), _ToprfAuthClient_encryptor = new WeakMap(), _ToprfAuthClient_instances = new WeakSet(), _ToprfAuthClient_isValidAuthResponse = function _ToprfAuthClient_isValidAuthResponse(authResponse) {
    if (authResponse === undefined || authResponse === null) {
        return false;
    }
    const parsedAuthResponse = JSON.parse(authResponse);
    return parsedAuthResponse.nodeAuthTokens !== undefined;
}, _ToprfAuthClient_generateMockNodeAuthTokens = function _ToprfAuthClient_generateMockNodeAuthTokens(verifier, verifierID) {
    // generate 5 mock nodeAuthTokens
    const nodeAuthTokens = Array.from({ length: 5 }, (_, index) => ({
        nodeAuthToken: `nodeAuthToken-${index}-${verifier}-${verifierID}`,
        nodeIndex: index,
    }));
    return nodeAuthTokens;
};
//# sourceMappingURL=ToprfClient.mjs.map
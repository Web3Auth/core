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
var _ToprfAuthClient_mockAuthStore, _ToprfAuthClient_mockMetadataStore, _ToprfAuthClient_encryptor;
Object.defineProperty(exports, "__esModule", { value: true });
exports.ToprfAuthClient = void 0;
const encryption_1 = require("./encryption.cjs");
const MetadataStore_1 = require("./MetadataStore.cjs");
// TODO: remove the class once the toprf-sdk is ready
// This class is a mock implementation for the toprf-sdk
class ToprfAuthClient {
    constructor() {
        _ToprfAuthClient_mockAuthStore.set(this, new MetadataStore_1.MetadataStore('auth'));
        _ToprfAuthClient_mockMetadataStore.set(this, new MetadataStore_1.MetadataStore('metadata'));
        // TODO: remove this once the toprf-sdk is ready
        // encryptions/signings should be done in the toprf-sdk
        _ToprfAuthClient_encryptor.set(this, void 0);
        __classPrivateFieldSet(this, _ToprfAuthClient_encryptor, new encryption_1.EncryptorDecryptor(), "f");
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
        if (authenticationResult === undefined || authenticationResult === null) {
            // generate mock nodeAuthTokens
            nodeAuthTokens = Array.from({ length: params.indexes.length }, (_, index) => ({
                nodeAuthToken: `nodeAuthToken-${index}-${params.verifier}-${params.verifierID}`,
                nodeIndex: params.indexes[index],
            }));
            const data = JSON.stringify({
                nodeAuthTokens,
                hasValidEncKey: false,
            });
            await __classPrivateFieldGet(this, _ToprfAuthClient_mockAuthStore, "f").set(key, data);
        }
        else {
            const parsedAuthenticationResult = JSON.parse(authenticationResult);
            nodeAuthTokens = parsedAuthenticationResult.nodeAuthTokens;
            hasValidEncKey = parsedAuthenticationResult.hasValidEncKey;
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
        return {
            encKey,
        };
    }
    async storeSecretData(params) {
        const { nodeAuthTokens, encKey, secretData } = params;
        const encryptedSecretData = __classPrivateFieldGet(this, _ToprfAuthClient_encryptor, "f").encrypt(encKey, secretData);
        console.log('encryptedSecretData', encryptedSecretData);
        const key = nodeAuthTokens.reduce((acc, token) => `${acc}:${token.nodeAuthToken}`, '');
        await __classPrivateFieldGet(this, _ToprfAuthClient_mockMetadataStore, "f").set(key, encryptedSecretData);
        return {
            encKey,
            encryptedSecretData,
        };
    }
    async fetchSecretData(params) {
        const key = params.nodeAuthTokens.reduce((acc, token) => `${acc}:${token.nodeAuthToken}`, '');
        const encryptedSecretData = await __classPrivateFieldGet(this, _ToprfAuthClient_mockMetadataStore, "f").get(key);
        console.log('encryptedSecretData', encryptedSecretData);
        const secretData = encryptedSecretData
            ? __classPrivateFieldGet(this, _ToprfAuthClient_encryptor, "f").decrypt(params.encKey, encryptedSecretData)
            : null;
        return {
            encKey: params.encKey,
            secretData: secretData ? [secretData] : null,
        };
    }
}
exports.ToprfAuthClient = ToprfAuthClient;
_ToprfAuthClient_mockAuthStore = new WeakMap(), _ToprfAuthClient_mockMetadataStore = new WeakMap(), _ToprfAuthClient_encryptor = new WeakMap();
//# sourceMappingURL=ToprfClient.cjs.map
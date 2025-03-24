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
var _ToprfAuthClient_instances, _ToprfAuthClient_mockAuthStore, _ToprfAuthClient_mockMetadataStore, _ToprfAuthClient_encryptor, _ToprfAuthClient_encryptSecretData, _ToprfAuthClient_decryptSecretData;
// TODO: remove the class once the toprf-sdk is ready
// This class is a mock implementation for the toprf-sdk
export class ToprfAuthClient {
    constructor(encryptor) {
        _ToprfAuthClient_instances.add(this);
        _ToprfAuthClient_mockAuthStore.set(this, new Map());
        _ToprfAuthClient_mockMetadataStore.set(this, new Map());
        // TODO: remove this once the toprf-sdk is ready
        // encryptions/signings should be done in the toprf-sdk
        _ToprfAuthClient_encryptor.set(this, void 0);
        __classPrivateFieldSet(this, _ToprfAuthClient_encryptor, encryptor, "f");
    }
    /**
     * Mock implementation of the authenticate method
     *
     * @param params - The parameters for the authentication
     * @returns The authentication result
     */
    async authenticate(params) {
        const key = `${params.verifier}:${params.verifierID}`;
        const stringifiedNodeAuthTokens = __classPrivateFieldGet(this, _ToprfAuthClient_mockAuthStore, "f").get(key);
        const hasValidEncKey = Boolean(stringifiedNodeAuthTokens);
        let nodeAuthTokens;
        if (stringifiedNodeAuthTokens === undefined) {
            // generate mock nodeAuthTokens
            nodeAuthTokens = Array.from({ length: params.indexes.length }, (_, index) => ({
                nodeAuthToken: `nodeAuthToken-${index}-${params.verifier}-${params.verifierID}`,
                nodeIndex: params.indexes[index],
            }));
            __classPrivateFieldGet(this, _ToprfAuthClient_mockAuthStore, "f").set(key, JSON.stringify(nodeAuthTokens));
        }
        else {
            nodeAuthTokens = JSON.parse(stringifiedNodeAuthTokens);
        }
        // TODO: do the threshold check
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
        // NOTE: this is a mock implementation
        // actual implementation involves threshold oprf
        const cryptoKey = await __classPrivateFieldGet(this, _ToprfAuthClient_encryptor, "f").keyFromPassword(params.password);
        const key = 'key' in cryptoKey ? cryptoKey.key : cryptoKey;
        const encKey = await __classPrivateFieldGet(this, _ToprfAuthClient_encryptor, "f").exportKey(key);
        return {
            encKey,
        };
    }
    async storeSecretData(params) {
        const { nodeAuthTokens, encKey, secretData } = params;
        const encryptedSecretData = await __classPrivateFieldGet(this, _ToprfAuthClient_instances, "m", _ToprfAuthClient_encryptSecretData).call(this, encKey, secretData);
        const key = nodeAuthTokens.reduce((acc, token) => `${acc}:${token.nodeAuthToken}`, '');
        __classPrivateFieldGet(this, _ToprfAuthClient_mockMetadataStore, "f").set(key, encryptedSecretData);
        return {
            encKey,
            encryptedSecretData,
        };
    }
    async fetchSecretData(params) {
        const { encKey } = await this.createEncKey(params);
        const key = params.nodeAuthTokens.reduce((acc, token) => `${acc}:${token.nodeAuthToken}`, '');
        const encryptedSecretData = __classPrivateFieldGet(this, _ToprfAuthClient_mockMetadataStore, "f").get(key);
        const secretData = encryptedSecretData
            ? await __classPrivateFieldGet(this, _ToprfAuthClient_instances, "m", _ToprfAuthClient_decryptSecretData).call(this, encKey, encryptedSecretData)
            : null;
        return {
            encKey,
            secretData: secretData ? [secretData] : null,
        };
    }
}
_ToprfAuthClient_mockAuthStore = new WeakMap(), _ToprfAuthClient_mockMetadataStore = new WeakMap(), _ToprfAuthClient_encryptor = new WeakMap(), _ToprfAuthClient_instances = new WeakSet(), _ToprfAuthClient_encryptSecretData = async function _ToprfAuthClient_encryptSecretData(encKeyString, secretData) {
    const encryptionKey = await __classPrivateFieldGet(this, _ToprfAuthClient_encryptor, "f").importKey(encKeyString);
    const encryptedSecretData = await __classPrivateFieldGet(this, _ToprfAuthClient_encryptor, "f").encryptWithKey(encryptionKey, secretData);
    return JSON.stringify(encryptedSecretData);
}, _ToprfAuthClient_decryptSecretData = async function _ToprfAuthClient_decryptSecretData(encKeyString, encryptedSecretData) {
    let encryptedResult;
    try {
        encryptedResult = JSON.parse(encryptedSecretData);
    }
    catch (error) {
        console.error(error);
        throw new Error('Fail to encrypt. Invalid data');
    }
    const decryptionKey = await __classPrivateFieldGet(this, _ToprfAuthClient_encryptor, "f").importKey(encKeyString);
    const decryptedResult = await __classPrivateFieldGet(this, _ToprfAuthClient_encryptor, "f").decryptWithKey(decryptionKey, encryptedResult);
    return decryptedResult;
};
//# sourceMappingURL=ToprfClient.mjs.map
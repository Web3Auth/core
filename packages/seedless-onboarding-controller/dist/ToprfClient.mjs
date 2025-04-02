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
import { EncryptorDecryptor } from "./encryption.mjs";
import { MetadataStore } from "./MetadataStore.mjs";
// TODO: remove the class once the toprf-sdk is ready
// This class is a mock implementation for the toprf-sdk
export class ToprfAuthClient {
    constructor() {
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
        const stringifiedNodeAuthTokens = await __classPrivateFieldGet(this, _ToprfAuthClient_mockAuthStore, "f").get(key);
        const hasValidEncKey = Boolean(stringifiedNodeAuthTokens);
        let nodeAuthTokens;
        if (stringifiedNodeAuthTokens === undefined ||
            stringifiedNodeAuthTokens === null) {
            // generate mock nodeAuthTokens
            nodeAuthTokens = Array.from({ length: params.indexes.length }, (_, index) => ({
                nodeAuthToken: `nodeAuthToken-${index}-${params.verifier}-${params.verifierID}`,
                nodeIndex: params.indexes[index],
            }));
            await __classPrivateFieldGet(this, _ToprfAuthClient_mockAuthStore, "f").set(key, JSON.stringify(nodeAuthTokens));
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
        const { encKey } = await this.createEncKey(params);
        console.log('encKey', encKey);
        const key = params.nodeAuthTokens.reduce((acc, token) => `${acc}:${token.nodeAuthToken}`, '');
        const encryptedSecretData = await __classPrivateFieldGet(this, _ToprfAuthClient_mockMetadataStore, "f").get(key);
        console.log('encryptedSecretData', encryptedSecretData);
        const secretData = encryptedSecretData
            ? __classPrivateFieldGet(this, _ToprfAuthClient_encryptor, "f").decrypt(encKey, encryptedSecretData)
            : null;
        return {
            encKey,
            secretData: secretData ? [secretData] : null,
        };
    }
}
_ToprfAuthClient_mockAuthStore = new WeakMap(), _ToprfAuthClient_mockMetadataStore = new WeakMap(), _ToprfAuthClient_encryptor = new WeakMap();
//# sourceMappingURL=ToprfClient.mjs.map
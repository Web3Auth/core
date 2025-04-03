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
var _MetadataStore_baseURL, _MetadataStore_keyPrefix;
Object.defineProperty(exports, "__esModule", { value: true });
exports.MetadataStore = void 0;
class MetadataStore {
    constructor(keyPrefix) {
        // Mock Metadata Store URL
        _MetadataStore_baseURL.set(this, 'https://mock-simple-auth.sapphire-dev-2-1.authnetwork.dev');
        _MetadataStore_keyPrefix.set(this, void 0);
        __classPrivateFieldSet(this, _MetadataStore_keyPrefix, keyPrefix, "f");
    }
    async set(key, data) {
        const url = `${__classPrivateFieldGet(this, _MetadataStore_baseURL, "f")}/${__classPrivateFieldGet(this, _MetadataStore_keyPrefix, "f")}/set`;
        const metadataKey = `${__classPrivateFieldGet(this, _MetadataStore_keyPrefix, "f")}_${key}`;
        const payload = JSON.stringify({ key: metadataKey, data });
        const response = await fetch(url, {
            headers: {
                'Content-Type': 'application/json',
            },
            method: 'POST',
            body: payload,
        });
        if (!response.ok) {
            throw new Error('Failed to set data');
        }
    }
    async get(key) {
        const url = `${__classPrivateFieldGet(this, _MetadataStore_baseURL, "f")}/${__classPrivateFieldGet(this, _MetadataStore_keyPrefix, "f")}/get`;
        const metadataKey = `${__classPrivateFieldGet(this, _MetadataStore_keyPrefix, "f")}_${key}`;
        const response = await fetch(url, {
            headers: {
                'Content-Type': 'application/json',
            },
            method: 'POST',
            body: JSON.stringify({ key: metadataKey }),
        });
        if (!response.ok) {
            throw new Error('Failed to get data');
        }
        const data = await response.json();
        return data.message;
    }
}
exports.MetadataStore = MetadataStore;
_MetadataStore_baseURL = new WeakMap(), _MetadataStore_keyPrefix = new WeakMap();
//# sourceMappingURL=MetadataStore.cjs.map
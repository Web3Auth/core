export declare class MetadataStore {
    #private;
    constructor(keyPrefix: string);
    set(key: string, data: string): Promise<void>;
    get(key: string): Promise<string | undefined>;
}
//# sourceMappingURL=MetadataStore.d.cts.map
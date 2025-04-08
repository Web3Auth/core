export declare class MetadataStore {
    #private;
    constructor(keyPrefix: string);
    set(key: string, data: string): Promise<void>;
    get<T extends string | string[]>(key: string): Promise<T>;
}
//# sourceMappingURL=MetadataStore.d.cts.map
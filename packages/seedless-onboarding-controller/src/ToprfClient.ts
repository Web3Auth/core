import { EncryptorDecryptor } from './encryption';
import { MetadataStore } from './MetadataStore';
import type { NodeAuthTokens } from './types';

export type AuthenticationParams = {
  // for now we only support one idToken, in future we will support multiple to remove commitment call
  // so leaving it as an array for future use
  idTokens: string[];
  endpoints: string[];
  indexes: number[];
  verifier: string;
  verifierID: string;
};

export type AuthenticationResult = {
  /**
   * The tokens issued by the nodes on verifying the idTokens
   */
  nodeAuthTokens: NodeAuthTokens;
  /**
   * The public key of the share if the user is an existing user
   */
  existingEncKeyPublicData?: {
    pubKeyX: string;
    pubKeyY: string;
    keyIndex: number;
  };
  /**
   * Whether the user is an existing user
   */
  hasValidEncKey: boolean;
};

export type CreateEncKeyParams = {
  /**
   * The tokens issued by the nodes on verifying the idToken.
   */
  nodeAuthTokens: NodeAuthTokens;
  /**
   * The password of the user.
   */
  password: string;
};

export type CreateEncKeyResult = {
  /**
   * The encryption key which is used to decrypt the secret data. This key is
   * generated by client and threshold shared with the nodes using TOPRF
   * protocol.
   */
  encKey: string;
};

export type StoreSecretDataParams = {
  /**
   * The tokens issued by the nodes on verifying the idTokens
   */
  nodeAuthTokens: NodeAuthTokens;
  /**
   * The encryption key under which the secret data will be encrypted.
   */
  encKey: string;
  /**
   * The secret data in hex encoding.
   */
  secretData: string;
};

export type StoreSecretDataResult = {
  /**
   * The encryption key which is used to decrypt the secret data.
   * This key is generated by client and threshold shared with the nodes using TOPRF protocol.
   */
  encKey: string;
  /**
   * The encrypted secret data
   */
  encryptedSecretData: string;
};

export type FetchSecretDataParams = {
  /**
   * The tokens issued by the nodes on verifying the idToken.
   */
  nodeAuthTokens: NodeAuthTokens;
  /**
   * The password of the user.
   */
  password: string;
};

export type FetchSecretDataResult = {
  /**
   * The encryption key which is used to decrypt the secret data.
   * This key is generated by client and threshold shared with the nodes using TOPRF protocol.
   */
  encKey: string;
  /**
   * The secret data to be fetched
   */
  secretData: string[] | null;
};

// TODO: remove the class once the toprf-sdk is ready
// This class is a mock implementation for the toprf-sdk
export class ToprfAuthClient {
  readonly #mockAuthStore: MetadataStore = new MetadataStore('auth');

  readonly #mockMetadataStore: MetadataStore = new MetadataStore('metadata');

  // TODO: remove this once the toprf-sdk is ready
  // encryptions/signings should be done in the toprf-sdk
  readonly #encryptor: EncryptorDecryptor;

  constructor() {
    this.#encryptor = new EncryptorDecryptor();
  }

  /**
   * Mock implementation of the authenticate method
   *
   * @param params - The parameters for the authentication
   * @returns The authentication result
   */
  async authenticate(
    params: AuthenticationParams,
  ): Promise<AuthenticationResult> {
    const key = `${params.verifier}:${params.verifierID}`;
    const stringifiedNodeAuthTokens = await this.#mockAuthStore.get(key);
    const hasValidEncKey = Boolean(stringifiedNodeAuthTokens);
    let nodeAuthTokens: NodeAuthTokens;

    if (
      stringifiedNodeAuthTokens === undefined ||
      stringifiedNodeAuthTokens === null
    ) {
      // generate mock nodeAuthTokens
      nodeAuthTokens = Array.from(
        { length: params.indexes.length },
        (_, index) => ({
          nodeAuthToken: `nodeAuthToken-${index}-${params.verifier}-${params.verifierID}`,
          nodeIndex: params.indexes[index],
        }),
      );
      await this.#mockAuthStore.set(key, JSON.stringify(nodeAuthTokens));
    } else {
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
  async createEncKey(params: CreateEncKeyParams): Promise<CreateEncKeyResult> {
    const encKey = this.#encryptor.keyFromPassword(params.password);
    return {
      encKey,
    };
  }

  async storeSecretData(
    params: StoreSecretDataParams,
  ): Promise<StoreSecretDataResult> {
    const { nodeAuthTokens, encKey, secretData } = params;

    const encryptedSecretData = this.#encryptor.encrypt(encKey, secretData);

    console.log('encryptedSecretData', encryptedSecretData);

    const key = nodeAuthTokens.reduce(
      (acc, token) => `${acc}:${token.nodeAuthToken}`,
      '',
    );
    await this.#mockMetadataStore.set(key, encryptedSecretData);

    return {
      encKey,
      encryptedSecretData,
    };
  }

  async fetchSecretData(
    params: FetchSecretDataParams,
  ): Promise<FetchSecretDataResult> {
    const { encKey } = await this.createEncKey(params);
    console.log('encKey', encKey);

    const key = params.nodeAuthTokens.reduce(
      (acc, token) => `${acc}:${token.nodeAuthToken}`,
      '',
    );
    const encryptedSecretData = await this.#mockMetadataStore.get(key);
    console.log('encryptedSecretData', encryptedSecretData);

    const secretData = encryptedSecretData
      ? this.#encryptor.decrypt(encKey, encryptedSecretData)
      : null;

    return {
      encKey,
      secretData: secretData ? [secretData] : null,
    };
  }
}

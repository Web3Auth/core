export class MetadataStore {
  // Mock Metadata Store URL
  readonly #baseURL: string =
    'mock-simple-auth.sapphire-dev-2-1.authnetwork.dev';

  readonly #keyPrefix: string;

  constructor(keyPrefix: string) {
    this.#keyPrefix = keyPrefix;
  }

  async set(key: string, data: string) {
    const url = `${this.#baseURL}/${this.#keyPrefix}/set`;
    const metadataKey = `${this.#keyPrefix}_${key}`;
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

  async get(key: string): Promise<string | undefined> {
    const url = `${this.#baseURL}/${this.#keyPrefix}/get`;
    const metadataKey = `${this.#keyPrefix}_${key}`;

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

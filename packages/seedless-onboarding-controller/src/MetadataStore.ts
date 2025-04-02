export class MetadataStore {
  // Mock Metadata Store URL
  readonly #baseURL: string = 'http://localhost:5051/eval';

  readonly #keyPrefix: string;

  constructor(keyPrefix: string) {
    this.#keyPrefix = keyPrefix;
  }

  async set(key: string, data: string) {
    const metadataKey = `${this.#keyPrefix}_${key}`;

    const response = await fetch(`${this.#baseURL}/option-2-write`, {
      headers: {
        'Content-Type': 'application/json',
      },
      method: 'POST',
      body: JSON.stringify({ key: metadataKey, data }),
    });
    if (!response.ok) {
      throw new Error('Failed to set data');
    }
  }

  async get(key: string): Promise<string | undefined> {
    const metadataKey = `${this.#keyPrefix}_${key}`;

    const response = await fetch(`${this.#baseURL}/option-2-read`, {
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

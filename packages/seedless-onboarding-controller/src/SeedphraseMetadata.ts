import { SeedlessOnboardingControllerError } from './constants';

/**
 * SeedPhraseMetadata is a class that adds metadata to the seed phrase.
 *
 * It contains the seed phrase and the timestamp when it was created.
 * It is used to store the seed phrase in the metadata store.
 *
 * @example
 * ```ts
 * const seedPhraseMetadata = new SeedphraseMetadata(seedPhrase);
 * ```
 */
export class SeedphraseMetadata {
  readonly #seedPhrase: Uint8Array;

  readonly #timestamp: number;

  /**
   * Create a new SeedPhraseMetadata instance.
   *
   * @param seedPhrase - The seed phrase to add metadata to.
   * @param timestamp - The timestamp when the seed phrase was created.
   */
  constructor(seedPhrase: Uint8Array, timestamp: number = Date.now()) {
    this.#seedPhrase = seedPhrase;
    this.#timestamp = timestamp;
  }

  /**
   * Assert that the provided value is a valid seed phrase metadata.
   *
   * @param value - The value to check.
   * @throws If the value is not a valid seed phrase metadata.
   */
  static assertIsValidSeedPhraseMetadata(value: unknown) {
    if (
      !value ||
      typeof value !== 'object' ||
      !('seedPhrase' in value) ||
      typeof value.seedPhrase !== 'string' ||
      !('timestamp' in value) ||
      typeof value.timestamp !== 'number'
    ) {
      throw new Error(
        SeedlessOnboardingControllerError.InvalidSeedPhraseMetadata,
      );
    }
  }

  /**
   * Parse and create the SeedPhraseMetadata instance from the raw metadata.
   *
   * @param rawMetadata - The raw metadata.
   * @returns The parsed seed phrase metadata.
   */
  static fromRawMetadata(rawMetadata: Uint8Array): SeedphraseMetadata {
    const serializedMetadata = Buffer.from(rawMetadata).toString('utf-8');
    const parsedMetadata = JSON.parse(serializedMetadata);

    SeedphraseMetadata.assertIsValidSeedPhraseMetadata(parsedMetadata);

    const seedPhraseBytes = new Uint8Array(
      Buffer.from(parsedMetadata.seedPhrase, 'base64'),
    );

    return new SeedphraseMetadata(seedPhraseBytes, parsedMetadata.timestamp);
  }

  /**
   * Sort the seed phrases by timestamp.
   *
   * @param seedPhrases - The seed phrases to sort.
   * @param order - The order to sort the seed phrases. Default is `desc`.
   *
   * @returns The sorted seed phrases.
   */
  static sort(
    seedPhrases: SeedphraseMetadata[],
    order: 'asc' | 'desc' = 'desc',
  ): SeedphraseMetadata[] {
    return seedPhrases.sort((a, b) => {
      if (order === 'asc') {
        return a.timestamp - b.timestamp;
      }

      return b.timestamp - a.timestamp;
    });
  }

  get seedPhrase() {
    return this.#seedPhrase;
  }

  get timestamp() {
    return this.#timestamp;
  }

  /**
   * Serialize the seed phrase metadata and convert it to a Uint8Array.
   *
   * @returns The serialized SeedPhraseMetadata value in bytes.
   */
  toBytes(): Uint8Array {
    const b64SeedPhrase = Buffer.from(this.#seedPhrase).toString('base64');
    const serializedMetadata = JSON.stringify({
      seedPhrase: b64SeedPhrase,
      timestamp: this.#timestamp,
    });

    return new Uint8Array(Buffer.from(serializedMetadata, 'utf-8'));
  }
}

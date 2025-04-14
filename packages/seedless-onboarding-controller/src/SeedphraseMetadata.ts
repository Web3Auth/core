import {
  base64ToBytes,
  bytesToBase64,
  stringToBytes,
  bytesToString,
} from '@metamask/utils';

import { SeedlessOnboardingControllerError } from './constants';

type ISeedphraseMetadata = {
  seedPhrase: Uint8Array;
  timestamp: number;

  toBytes: () => Uint8Array;
};

// SeedphraseMetadata type without the seedPhrase and toBytes methods
// in which the seedPhrase is base64 encoded for more compacted metadata
type IBase64SeedphraseMetadata = Omit<
  ISeedphraseMetadata,
  'seedPhrase' | 'toBytes'
> & {
  seedPhrase: string; // base64 encoded string
};

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
export class SeedphraseMetadata implements ISeedphraseMetadata {
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
  static assertIsBase64SeedphraseMetadata(
    value: unknown,
  ): asserts value is IBase64SeedphraseMetadata {
    if (
      typeof value !== 'object' ||
      !value ||
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
    const serializedMetadata = bytesToString(rawMetadata);
    const parsedMetadata = JSON.parse(serializedMetadata);

    SeedphraseMetadata.assertIsBase64SeedphraseMetadata(parsedMetadata);

    const seedPhraseBytes = base64ToBytes(parsedMetadata.seedPhrase);
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
    // encode the raw SeedPhrase to base64 encoded string
    // to create more compacted metadata
    const b64SeedPhrase = bytesToBase64(this.#seedPhrase);

    // serialize the metadata to a JSON string
    const serializedMetadata = JSON.stringify({
      seedPhrase: b64SeedPhrase,
      timestamp: this.#timestamp,
    });

    // convert the serialized metadata to bytes(Uint8Array)
    return stringToBytes(serializedMetadata);
  }
}

import type {
  ControllerGetStateAction,
  ControllerStateChangeEvent,
  RestrictedMessenger,
} from '@metamask/base-controller';
import type { KeyringControllerStateChangeEvent } from '@metamask/keyring-controller';
import type { NodeAuthTokens } from '@metamask/toprf-secure-backup';
import type { Json } from '@metamask/utils';
import type { MutexInterface } from 'async-mutex';

import type { controllerName, EWeb3AuthNetwork } from './constants';

// State
export type SeedlessOnboardingControllerState = {
  /**
   * Encrypted array of serialized keyrings data.
   */
  vault?: string;

  /**
   * The node auth tokens from OAuth User authentication after the Social login.
   *
   * This values are used to authenticate users when they go through the Seedless Onboarding flow.
   */
  nodeAuthTokens?: NodeAuthTokens;

  /**
   * The hashes of the seed phrase backups.
   *
   * This is to facilitate the UI to display backup status of the seed phrases.
   */
  backupHashes: string[];
};

// Actions
export type SeedlessOnboardingControllerGetStateActions =
  ControllerGetStateAction<
    typeof controllerName,
    SeedlessOnboardingControllerState
  >;

export type AllowedActions = SeedlessOnboardingControllerGetStateActions;

export type SeedlessOnboardingControllerStateChangeEvent =
  ControllerStateChangeEvent<
    typeof controllerName,
    SeedlessOnboardingControllerState
  >;

// events allowed to be subscribed
export type AllowedEvents =
  | KeyringControllerStateChangeEvent
  | SeedlessOnboardingControllerStateChangeEvent;

// Messenger
export type SeedlessOnboardingControllerMessenger = RestrictedMessenger<
  typeof controllerName,
  AllowedActions,
  AllowedEvents,
  AllowedActions['type'],
  AllowedEvents['type']
>;

/**
 * @description Encryptor interface for encrypting and decrypting seedless onboarding vault.
 */
export type Encryptor = {
  /**
   * Encrypts the given object with the given password.
   *
   * @param password - The password to encrypt with.
   * @param object - The object to encrypt.
   * @returns The encrypted string.
   */
  encrypt: (password: string, object: Json) => Promise<string>;
  /**
   * Decrypts the given encrypted string with the given password.
   *
   * @param password - The password to decrypt with.
   * @param encryptedString - The encrypted string to decrypt.
   * @returns The decrypted object.
   */
  decrypt: (password: string, encryptedString: string) => Promise<unknown>;
};

export type SeedlessOnboardingControllerOptions = {
  messenger: SeedlessOnboardingControllerMessenger;

  network?: EWeb3AuthNetwork;

  /**
   * @description Initial state to set on this controller.
   */
  state?: SeedlessOnboardingControllerState;

  /**
   * @description Encryptor used for encryption and decryption of data.
   * @default WebCryptoAPI
   */
  encryptor?: Encryptor;
};

/**
 * A function executed within a mutually exclusive lock, with
 * a mutex releaser in its option bag.
 *
 * @param releaseLock - A function to release the lock.
 */
export type MutuallyExclusiveCallback<Result> = ({
  releaseLock,
}: {
  releaseLock: MutexInterface.Releaser;
}) => Promise<Result>;

/**
 * @description The structure of the data which is serialized and stored in the vault.
 */
export type VaultData = {
  /**
   * The node auth tokens from OAuth User authentication after the Social login.
   */
  authTokens: NodeAuthTokens;
  /**
   * The encryption key to encrypt the seed phrase.
   */
  toprfEncryptionKey: string;
  /**
   * The authentication key pair to authenticate the TOPRF.
   */
  toprfAuthKeyPair: string;
};

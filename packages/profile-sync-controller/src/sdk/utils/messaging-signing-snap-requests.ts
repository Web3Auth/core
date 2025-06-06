import type { Eip1193Provider } from 'ethers';

export type Snap = {
  permissionName: string;
  id: string;
  version: string;
  initialPermissions: Record<string, unknown>;
};
export type GetSnapsResponse = Record<string, Snap>;

export const SNAP_ORIGIN = 'npm:@metamask/message-signing-snap';

/**
 * Requests Connection to the Message Signing Snap
 *
 * @param provider - MetaMask Wallet Provider
 * @returns snap connect result
 */
export async function connectSnap(provider: Eip1193Provider): Promise<string> {
  const result: string = await provider.request({
    method: 'wallet_requestSnaps',
    params: {
      [SNAP_ORIGIN]: {},
    },
  });

  return result;
}

/**
 * Gets Snaps from a MetaMask Wallet
 *
 * @param provider - MetaMask Wallet Provider
 * @returns All currently installed snaps.
 */
export async function getSnaps(
  provider: Eip1193Provider,
): Promise<GetSnapsResponse> {
  const result: GetSnapsResponse = await provider.request({
    method: 'wallet_getSnaps',
  });

  return result;
}

/**
 * Check if snap is connected
 *
 * @param provider - MetaMask Wallet Provider
 * @returns if snap is connected
 */
export async function isSnapConnected(
  provider: Eip1193Provider,
): Promise<boolean> {
  try {
    const snaps = await getSnaps(provider);
    if (!snaps) {
      return false;
    }
    return Object.keys(snaps).includes(SNAP_ORIGIN);
  } catch (e) {
    console.error('Failed to determine if snap is connected', e);
    return false;
  }
}

export const MESSAGE_SIGNING_SNAP = {
  async getPublicKey(provider: Eip1193Provider, entropySourceId?: string) {
    const publicKey: string = await provider.request({
      method: 'wallet_invokeSnap',
      params: {
        snapId: SNAP_ORIGIN,
        request: {
          method: 'getPublicKey',
          ...(entropySourceId ? { params: { entropySourceId } } : {}),
        },
      },
    });

    return publicKey;
  },

  async signMessage(
    provider: Eip1193Provider,
    message: `metamask:${string}`,
    entropySourceId?: string,
  ) {
    const signedMessage: string = await provider?.request({
      method: 'wallet_invokeSnap',
      params: {
        snapId: SNAP_ORIGIN,
        request: {
          method: 'signMessage',
          params: {
            message,
            ...(entropySourceId ? { entropySourceId } : {}),
          },
        },
      },
    });

    return signedMessage;
  },
};

/**
 * Asserts that a message starts with "metamask:"
 *
 * @param message - The message to check.
 */
export function assertMessageStartsWithMetamask(
  message: string,
): asserts message is `metamask:${string}` {
  if (!message.startsWith('metamask:')) {
    throw new Error('Message must start with "metamask:"');
  }
}

import type { AccountsController } from '@metamask/accounts-controller';
import { Messenger } from '@metamask/base-controller';
import {
  NFT_API_BASE_URL,
  ChainId,
  InfuraNetworkType,
} from '@metamask/controller-utils';
import {
  getDefaultNetworkControllerState,
  NetworkClientType,
} from '@metamask/network-controller';
import type {
  NetworkClient,
  NetworkClientConfiguration,
  NetworkClientId,
  NetworkController,
  NetworkState,
} from '@metamask/network-controller';
import {
  getDefaultPreferencesState,
  type PreferencesState,
} from '@metamask/preferences-controller';
import nock from 'nock';
import * as sinon from 'sinon';

import { FakeBlockTracker } from '../../../tests/fake-block-tracker';
import { FakeProvider } from '../../../tests/fake-provider';
import { advanceTime } from '../../../tests/helpers';
import { createMockInternalAccount } from '../../accounts-controller/src/tests/mocks';
import {
  buildMockFindNetworkClientIdByChainId,
  buildMockGetNetworkClientById,
} from '../../network-controller/tests/helpers';
import { Source } from './constants';
import { getDefaultNftControllerState } from './NftController';
import {
  NftDetectionController,
  BlockaidResultType,
  MAX_GET_COLLECTION_BATCH_SIZE,
  type AllowedActions,
  type AllowedEvents,
} from './NftDetectionController';
import * as constants from './NftDetectionController';

const controllerName = 'NftDetectionController' as const;

const defaultSelectedAccount = createMockInternalAccount();

describe('NftDetectionController', () => {
  let clock: sinon.SinonFakeTimers;

  beforeEach(async () => {
    clock = sinon.useFakeTimers();

    nock(NFT_API_BASE_URL)
      .persist()
      .get(
        `/users/0x1/tokens?chainIds=1&limit=50&includeTopBid=true&continuation=`,
      )
      .reply(200, {
        tokens: [
          {
            token: {
              chainId: 1,
              contract: '0xCE7ec4B2DfB30eB6c0BB5656D33aAd6BFb4001Fc',
              tokenId: '2577',
              kind: 'erc721',
              name: 'Remilio 632',
              image: 'https://imgtest',
              imageSmall: 'https://imgSmall',
              imageLarge: 'https://imglarge',
              metadata: {
                imageOriginal: 'https://remilio.org/remilio/632.png',
                imageMimeType: 'image/png',
                tokenURI: 'https://remilio.org/remilio/json/632',
              },
              description:
                "Redacted Remilio Babies is a collection of 10,000 neochibi pfpNFT's expanding the Milady Maker paradigm with the introduction of young J.I.T. energy and schizophrenic reactionary aesthetics. We are #REMILIONAIREs.",
              rarityScore: 343.443,
              rarityRank: 8872,
              supply: '1',
              isSpam: false,
            },
          },
          {
            token: {
              chainId: 1,
              contract: '0x0B0fa4fF58D28A88d63235bd0756EDca69e49e6d',
              kind: 'erc721',
              name: 'ID 2578',
              description: 'Description 2578',
              image: 'https://imgtest',
              imageSmall: 'https://imgSmall',
              imageLarge: 'https://imglarge',
              tokenId: '2578',
              metadata: {
                imageOriginal: 'https://remilio.org/remilio/632.png',
                imageMimeType: 'image/png',
                tokenURI: 'https://remilio.org/remilio/json/632',
              },
              rarityScore: 343.443,
              rarityRank: 8872,
              supply: '1',
              isSpam: false,
            },
          },
          {
            token: {
              chainId: 1,
              contract: '0xebE4e5E773AFD2bAc25De0cFafa084CFb3cBf1eD',
              kind: 'erc721',
              name: 'ID 2574',
              description: 'Description 2574',
              image: 'image/2574.png',
              tokenId: '2574',
              metadata: {
                imageOriginal: 'imageOriginal/2574.png',
                imageMimeType: 'image/png',
                tokenURI: 'tokenURITest',
              },
              isSpam: false,
            },
          },
        ],
      })
      .get(
        `/users/0x1/tokens?chainIds=1&chainIds=59144&limit=50&includeTopBid=true&continuation=`,
      )
      .reply(200, {
        tokens: [
          {
            token: {
              chainId: 59144,
              contract: '0xebE4e5E773AFD2bAc25De0cFafa084CFb3cBf1e5',
              kind: 'erc721',
              name: 'ID 2',
              description: 'Description 2',
              image: 'image/2.png',
              tokenId: '2',
              metadata: {
                imageOriginal: 'imageOriginal/2.png',
                imageMimeType: 'image/png',
                tokenURI: 'tokenURITest',
              },
              isSpam: false,
            },
          },
          {
            token: {
              chainId: 1,
              contract: '0xebE4e5E773AFD2bAc25De0cFafa084CFb3cBf1eD',
              kind: 'erc721',
              name: 'ID 2574',
              description: 'Description 2574',
              image: 'image/2574.png',
              tokenId: '2574',
              metadata: {
                imageOriginal: 'imageOriginal/2574.png',
                imageMimeType: 'image/png',
                tokenURI: 'tokenURITest',
              },
              isSpam: false,
            },
          },
        ],
      })
      .get(
        `/users/0x9/tokens?chainIds=1&limit=50&includeTopBid=true&continuation=`,
      )
      .reply(200, {
        tokens: [
          {
            token: {
              chainId: 1,
              contract: '0xebE4e5E773AFD2bAc25De0cFafa084CFb3cBf1eD',
              kind: 'erc721',
              name: 'ID 2574',
              description: 'Description 2574',
              image: 'image/2574.png',
              tokenId: '2574',
              metadata: {
                imageOriginal: 'imageOriginal/2574.png',
                imageMimeType: 'image/png',
                tokenURI: 'tokenURITest',
              },
              isSpam: false,
            },
          },
        ],
      })
      .get(
        `/users/0x123/tokens?chainIds=1&limit=50&includeTopBid=true&continuation=`,
      )
      .reply(200, {
        tokens: [
          {
            token: {
              chainId: 1,
              contract: '0xtest1',
              kind: 'erc721',
              name: 'ID 2574',
              description: 'Description 2574',
              image: 'image/2574.png',
              tokenId: '2574',
              metadata: {
                imageOriginal: 'imageOriginal/2574.png',
                imageMimeType: 'image/png',
                tokenURI: 'tokenURITest',
              },
              isSpam: false,
              collection: {
                id: '0xtest1',
              },
            },
            blockaidResult: {
              // TODO: Either fix this lint violation or explain why it's necessary to ignore.
              // eslint-disable-next-line @typescript-eslint/naming-convention
              result_type: BlockaidResultType.Benign,
            },
          },
          {
            token: {
              chainId: 1,
              contract: '0xtest2',
              kind: 'erc721',
              name: 'ID 2575',
              description: 'Description 2575',
              image: 'image/2575.png',
              tokenId: '2575',
              metadata: {
                imageOriginal: 'imageOriginal/2575.png',
                imageMimeType: 'image/png',
                tokenURI: 'tokenURITest',
              },
              isSpam: false,
              collection: {
                id: '0xtest2',
              },
            },
            blockaidResult: {
              // TODO: Either fix this lint violation or explain why it's necessary to ignore.
              // eslint-disable-next-line @typescript-eslint/naming-convention
              result_type: BlockaidResultType.Benign,
            },
          },
        ],
      })
      .get(
        `/users/0x12345/tokens?chainIds=1&limit=50&includeTopBid=true&continuation=`,
      )
      .reply(200, {
        tokens: [
          {
            token: {
              chainId: 1,
              contract: '0xtestCollection1',
              kind: 'erc721',
              name: 'ID 1',
              description: 'Description 1',
              image: 'image/1.png',
              tokenId: '1',
              metadata: {
                imageOriginal: 'imageOriginal/1.png',
                imageMimeType: 'image/png',
                tokenURI: 'tokenURITest',
              },
              isSpam: false,
              collection: {
                id: '0xtestCollection1',
              },
            },
            blockaidResult: {
              // TODO: Either fix this lint violation or explain why it's necessary to ignore.
              // eslint-disable-next-line @typescript-eslint/naming-convention
              result_type: BlockaidResultType.Benign,
            },
          },
          {
            token: {
              chainId: 1,
              contract: '0xtestCollection2',
              kind: 'erc721',
              name: 'ID 2',
              description: 'Description 2',
              image: 'image/2.png',
              tokenId: '2',
              metadata: {
                imageOriginal: 'imageOriginal/2.png',
                imageMimeType: 'image/png',
                tokenURI: 'tokenURITest',
              },
              isSpam: false,
              collection: {
                id: '0xtestCollection2',
              },
            },
          },
          {
            token: {
              chainId: 1,
              contract: '0xtestCollection3',
              kind: 'erc721',
              name: 'ID 3',
              description: 'Description 3',
              image: 'image/3.png',
              tokenId: '3',
              metadata: {
                imageOriginal: 'imageOriginal/3.png',
                imageMimeType: 'image/png',
                tokenURI: 'tokenURITest',
              },
              isSpam: false,
            },
            blockaidResult: {
              // TODO: Either fix this lint violation or explain why it's necessary to ignore.
              // eslint-disable-next-line @typescript-eslint/naming-convention
              result_type: BlockaidResultType.Malicious,
            },
          },
          {
            token: {
              chainId: 1,
              contract: '0xtestCollection4',
              kind: 'erc721',
              name: 'ID 4',
              description: 'Description 4',
              image: 'image/4.png',
              tokenId: '4',
              metadata: {
                imageOriginal: 'imageOriginal/4.png',
                imageMimeType: 'image/png',
                tokenURI: 'tokenURITest',
              },
              isSpam: true,
            },
            blockaidResult: {
              // TODO: Either fix this lint violation or explain why it's necessary to ignore.
              // eslint-disable-next-line @typescript-eslint/naming-convention
              result_type: BlockaidResultType.Benign,
            },
          },
          {
            token: {
              chainId: 1,
              contract: '0xtestCollection5',
              kind: 'erc721',
              name: 'ID 5',
              description: 'Description 5',
              image: 'image/5.png',
              tokenId: '5',
              metadata: {
                imageOriginal: 'imageOriginal/5.png',
                imageMimeType: 'image/png',
                tokenURI: 'tokenURITest',
              },
              isSpam: true,
            },
            blockaidResult: {
              // TODO: Either fix this lint violation or explain why it's necessary to ignore.
              // eslint-disable-next-line @typescript-eslint/naming-convention
              result_type: BlockaidResultType.Malicious,
            },
          },
        ],
      });
  });

  afterEach(() => {
    clock.restore();
    sinon.restore();
  });

  it('should call detect NFTs on mainnet', async () => {
    const mockGetSelectedAccount = jest
      .fn()
      .mockReturnValue(defaultSelectedAccount);
    await withController(
      {
        options: {},
        mockGetSelectedAccount,
      },
      async ({ controller, controllerEvents }) => {
        const mockNfts = sinon
          .stub(controller, 'detectNfts')
          .returns(Promise.resolve());
        controllerEvents.triggerPreferencesStateChange({
          ...getDefaultPreferencesState(),
          useNftDetection: true,
        });

        // call detectNfts
        await controller.detectNfts(['0x1']);
        expect(mockNfts.calledOnce).toBe(true);

        await advanceTime({
          clock,
          duration: 10,
        });

        expect(mockNfts.calledTwice).toBe(false);
      },
    );
  });

  it('should detect mainnet truthy', async () => {
    await withController(
      {
        mockNetworkState: {
          selectedNetworkClientId: 'mainnet',
        },
        mockPreferencesState: {
          selectedAddress: '',
        },
      },
      ({ controller }) => {
        expect(controller.isMainnet()).toBe(true);
      },
    );
  });

  it('should detect NFTs on Linea mainnet', async () => {
    const selectedAddress = '0x1';
    const selectedAccount = createMockInternalAccount({
      address: selectedAddress,
    });
    const mockGetSelectedAccount = jest.fn().mockReturnValue(selectedAccount);

    await withController(
      {
        mockNetworkState: {
          selectedNetworkClientId: InfuraNetworkType['linea-mainnet'],
        },
        mockGetSelectedAccount,
      },
      async ({ controller, controllerEvents }) => {
        controllerEvents.triggerPreferencesStateChange({
          ...getDefaultPreferencesState(),
          useNftDetection: true,
          selectedAddress,
        });
        // nock
        const mockApiCall = nock(NFT_API_BASE_URL)
          .get(`/users/${selectedAddress}/tokens`)
          .query({
            continuation: '',
            limit: '50',
            chainIds: '59144',
            includeTopBid: true,
          })
          .reply(200, {
            tokens: [],
          });

        // call detectNfts
        await controller.detectNfts(['0xe708']);

        expect(mockApiCall.isDone()).toBe(true);
      },
    );
  });

  it('should detect mainnet falsy', async () => {
    await withController(
      {
        mockNetworkState: {
          selectedNetworkClientId: 'goerli',
        },
        mockPreferencesState: {
          selectedAddress: '',
        },
      },
      ({ controller }) => {
        expect(controller.isMainnet()).toBe(false);
      },
    );
  });

  it('should return when detectNfts is called on a not supported network for detection', async () => {
    const selectedAddress = '0x1';
    const selectedAccount = createMockInternalAccount({
      address: selectedAddress,
    });
    const mockGetSelectedAccount = jest.fn().mockReturnValue(selectedAccount);
    await withController(
      {
        mockNetworkState: {
          selectedNetworkClientId: 'goerli',
        },
        mockPreferencesState: {},
        mockGetSelectedAccount,
      },
      async ({ controller }) => {
        const mockNfts = sinon.stub(controller, 'detectNfts');

        // nock
        const mockApiCall = nock(NFT_API_BASE_URL)
          .get(`/users/${selectedAddress}/tokens`)
          .query({
            continuation: '',
            limit: '50',
            chainIds: '1',
            includeTopBid: true,
          })
          .reply(200, {
            tokens: [],
          });

        // call detectNfts
        await controller.detectNfts(['0x507'], {
          userAddress: selectedAddress,
        });

        expect(mockNfts.called).toBe(true);
        expect(mockApiCall.isDone()).toBe(false);
      },
    );
  });

  it('should detect and add NFTs correctly when blockaid result is not included in response', async () => {
    const mockAddNft = jest.fn();
    const selectedAddress = '0x1';
    const selectedAccount = createMockInternalAccount({
      address: selectedAddress,
    });
    const mockGetSelectedAccount = jest.fn().mockReturnValue(selectedAccount);
    await withController(
      {
        options: { addNft: mockAddNft },
        mockPreferencesState: {},
        mockGetSelectedAccount,
      },
      async ({ controller, controllerEvents }) => {
        controllerEvents.triggerPreferencesStateChange({
          ...getDefaultPreferencesState(),
          useNftDetection: true,
        });

        // Mock /getCollections call

        nock(NFT_API_BASE_URL)
          .get(
            `/collections?contract=0xCE7ec4B2DfB30eB6c0BB5656D33aAd6BFb4001Fc&contract=0x0B0fa4fF58D28A88d63235bd0756EDca69e49e6d&contract=0xebE4e5E773AFD2bAc25De0cFafa084CFb3cBf1eD&chainId=1`,
          )
          .replyWithError(new Error('Failed to fetch'));

        // Wait for detect call triggered by preferences state change to settle
        await advanceTime({
          clock,
          duration: 1,
        });
        mockAddNft.mockReset();

        await controller.detectNfts(['0x1']);

        expect(mockAddNft).toHaveBeenCalledWith(
          '0xebE4e5E773AFD2bAc25De0cFafa084CFb3cBf1eD',
          '2574',
          'mainnet',
          {
            nftMetadata: {
              description: 'Description 2574',
              image: 'image/2574.png',
              name: 'ID 2574',
              standard: 'ERC721',
              imageOriginal: 'imageOriginal/2574.png',
              chainId: 1,
            },
            userAddress: selectedAccount.address,
            source: Source.Detected,
          },
        );
      },
    );
  });

  it('should detect and add NFTs correctly with an array of chainIds', async () => {
    const mockAddNft = jest.fn();
    const selectedAddress = '0x1';
    const selectedAccount = createMockInternalAccount({
      address: selectedAddress,
    });
    const mockGetSelectedAccount = jest.fn().mockReturnValue(selectedAccount);
    await withController(
      {
        options: { addNft: mockAddNft },
        mockPreferencesState: {},
        mockGetSelectedAccount,
      },
      async ({ controller, controllerEvents }) => {
        controllerEvents.triggerPreferencesStateChange({
          ...getDefaultPreferencesState(),
          useNftDetection: true,
        });

        // Mock /getCollections call

        nock(NFT_API_BASE_URL)
          .get(
            `/collections?contract=0xCE7ec4B2DfB30eB6c0BB5656D33aAd6BFb4001Fc&contract=0x0B0fa4fF58D28A88d63235bd0756EDca69e49e6d&contract=0xebE4e5E773AFD2bAc25De0cFafa084CFb3cBf1eD&chainId=1`,
          )
          .replyWithError(new Error('Failed to fetch'));

        // Wait for detect call triggered by preferences state change to settle
        await advanceTime({
          clock,
          duration: 1,
        });
        mockAddNft.mockReset();

        await controller.detectNfts(['0x1', '0xe708']);
        expect(mockAddNft).toHaveBeenNthCalledWith(
          1,
          '0xebE4e5E773AFD2bAc25De0cFafa084CFb3cBf1e5',
          '2',
          'linea-mainnet',
          {
            nftMetadata: {
              description: 'Description 2',
              image: 'image/2.png',
              name: 'ID 2',
              standard: 'ERC721',
              imageOriginal: 'imageOriginal/2.png',
              chainId: 59144,
            },
            userAddress: selectedAccount.address,
            source: Source.Detected,
          },
        );
        expect(mockAddNft).toHaveBeenNthCalledWith(
          2,
          '0xebE4e5E773AFD2bAc25De0cFafa084CFb3cBf1eD',
          '2574',
          'mainnet',
          {
            nftMetadata: {
              description: 'Description 2574',
              image: 'image/2574.png',
              name: 'ID 2574',
              standard: 'ERC721',
              imageOriginal: 'imageOriginal/2574.png',
              chainId: 1,
            },
            userAddress: selectedAccount.address,
            source: Source.Detected,
          },
        );
      },
    );
  });

  describe('getCollections', () => {
    it('should not call getCollections api when collection ids do not match contract address', async () => {
      const mockAddNft = jest.fn();
      const selectedAddress = 'Oxuser';
      const selectedAccount = createMockInternalAccount({
        address: selectedAddress,
      });
      const mockGetSelectedAccount = jest.fn().mockReturnValue(selectedAccount);
      await withController(
        {
          options: { addNft: mockAddNft },
          mockPreferencesState: {},
          mockGetSelectedAccount,
        },
        async ({ controller, controllerEvents }) => {
          controllerEvents.triggerPreferencesStateChange({
            ...getDefaultPreferencesState(),
            useNftDetection: true,
          });
          // Wait for detect call triggered by preferences state change to settle
          await advanceTime({
            clock,
            duration: 1,
          });
          mockAddNft.mockReset();
          nock(NFT_API_BASE_URL)
            .get(
              `/users/${selectedAddress}/tokens?chainIds=1&limit=50&includeTopBid=true&continuation=`,
            )
            .reply(200, {
              tokens: [
                {
                  token: {
                    chainId: 1,
                    contract: '0xtestCollection1',
                    kind: 'erc721',
                    name: 'ID 1',
                    description: 'Description 1',
                    image: 'image/1.png',
                    tokenId: '1',
                    metadata: {
                      imageOriginal: 'imageOriginal/1.png',
                      imageMimeType: 'image/png',
                      tokenURI: 'tokenURITest',
                    },
                    isSpam: false,
                    collection: {
                      id: '0xtestCollection1:1223',
                    },
                  },
                  blockaidResult: {
                    // TODO: Either fix this lint violation or explain why it's necessary to ignore.
                    // eslint-disable-next-line @typescript-eslint/naming-convention
                    result_type: BlockaidResultType.Benign,
                  },
                },
                {
                  token: {
                    chainId: 1,
                    contract: '0xtestCollection1',
                    kind: 'erc721',
                    name: 'ID 2',
                    description: 'Description 2',
                    image: 'image/2.png',
                    tokenId: '2',
                    metadata: {
                      imageOriginal: 'imageOriginal/2.png',
                      imageMimeType: 'image/png',
                      tokenURI: 'tokenURITest',
                    },
                    isSpam: false,
                    collection: {
                      id: '0xtestCollection1:34567',
                    },
                  },
                },
              ],
            });

          await controller.detectNfts(['0x1']);

          expect(mockAddNft).toHaveBeenCalledTimes(2);
          // In this test we mocked that reservoir returned 5 NFTs
          // the only NFTs we want to add are when isSpam=== false and (either no blockaid result returned or blockaid says "Benign")
          expect(mockAddNft).toHaveBeenNthCalledWith(
            1,
            '0xtestCollection1',
            '1',
            'mainnet',
            {
              nftMetadata: {
                description: 'Description 1',
                image: 'image/1.png',
                name: 'ID 1',
                standard: 'ERC721',
                imageOriginal: 'imageOriginal/1.png',
                collection: {
                  id: '0xtestCollection1:1223',
                },
                chainId: 1,
              },
              userAddress: selectedAccount.address,
              source: Source.Detected,
            },
          );
          expect(mockAddNft).toHaveBeenNthCalledWith(
            2,
            '0xtestCollection1',
            '2',
            'mainnet',
            {
              nftMetadata: {
                description: 'Description 2',
                image: 'image/2.png',
                name: 'ID 2',
                standard: 'ERC721',
                imageOriginal: 'imageOriginal/2.png',
                collection: {
                  id: '0xtestCollection1:34567',
                },
                chainId: 1,
              },
              userAddress: selectedAccount.address,
              source: Source.Detected,
            },
          );
        },
      );
    });
    it('should detect and add NFTs correctly when blockaid result is in response with unsuccessful getCollections', async () => {
      const mockAddNft = jest.fn();
      const selectedAddress = '0x123';
      const selectedAccount = createMockInternalAccount({
        address: selectedAddress,
      });
      const mockGetSelectedAccount = jest.fn().mockReturnValue(selectedAccount);
      await withController(
        {
          options: { addNft: mockAddNft },
          mockPreferencesState: {},
          mockGetSelectedAccount,
        },
        async ({ controller, controllerEvents }) => {
          controllerEvents.triggerPreferencesStateChange({
            ...getDefaultPreferencesState(),
            useNftDetection: true,
          });
          // Wait for detect call triggered by preferences state change to settle
          await advanceTime({
            clock,
            duration: 1,
          });
          mockAddNft.mockReset();

          nock(NFT_API_BASE_URL)
            .get(`/collections?contract=0xtest1&contract=0xtest2&chainId=1`)
            .replyWithError(new Error('Failed to fetch'));

          await controller.detectNfts(['0x1']);

          // Expect to be called twice
          expect(mockAddNft).toHaveBeenNthCalledWith(
            1,
            '0xtest1',
            '2574',
            'mainnet',
            {
              nftMetadata: {
                description: 'Description 2574',
                image: 'image/2574.png',
                name: 'ID 2574',
                standard: 'ERC721',
                imageOriginal: 'imageOriginal/2574.png',
                collection: {
                  id: '0xtest1',
                },
                chainId: 1,
              },
              userAddress: selectedAccount.address,
              source: Source.Detected,
            },
          );
          expect(mockAddNft).toHaveBeenNthCalledWith(
            2,
            '0xtest2',
            '2575',
            'mainnet',
            {
              nftMetadata: {
                description: 'Description 2575',
                image: 'image/2575.png',
                name: 'ID 2575',
                standard: 'ERC721',
                imageOriginal: 'imageOriginal/2575.png',
                collection: {
                  id: '0xtest2',
                },
                chainId: 1,
              },
              userAddress: selectedAccount.address,
              source: Source.Detected,
            },
          );
        },
      );
    });
    it('should detect and add NFTs correctly when blockaid result is in response with successful getCollections', async () => {
      const mockAddNft = jest.fn();
      const selectedAddress = '0x123';
      const selectedAccount = createMockInternalAccount({
        address: selectedAddress,
      });
      const mockGetSelectedAccount = jest.fn().mockReturnValue(selectedAccount);
      await withController(
        {
          options: { addNft: mockAddNft },
          mockPreferencesState: {},
          mockGetSelectedAccount,
        },
        async ({ controller, controllerEvents }) => {
          controllerEvents.triggerPreferencesStateChange({
            ...getDefaultPreferencesState(),
            useNftDetection: true,
          });
          // Wait for detect call triggered by preferences state change to settle
          await advanceTime({
            clock,
            duration: 1,
          });
          mockAddNft.mockReset();

          const testTopBid = {
            id: 'id',
            sourceDomain: 'opensea.io',
            price: {
              currency: {
                contract: '0x01',
                name: 'Wrapped Ether',
                symbol: 'WETH',
                decimals: 18,
              },
              amount: {
                raw: '201300000000000000',
                decimal: 0.2013,
                usd: 716.46131,
                native: 0.2013,
              },
              netAmount: {
                raw: '196267500000000000',
                decimal: 0.19627,
                usd: 698.54978,
                native: 0.19627,
              },
            },
            maker: 'testMaker',
            validFrom: 1719228327,
            validUntil: 1719228927,
          };

          nock(NFT_API_BASE_URL)
            .get(`/collections?contract=0xtest1&contract=0xtest2&chainId=1`)
            .reply(200, {
              collections: [
                {
                  id: '0xtest1',
                  chainId: 1,
                  creator: '0xcreator1',
                  openseaVerificationStatus: 'verified',
                  topBid: testTopBid,
                },
                {
                  id: '0xtest2',
                  chainId: 1,
                  creator: '0xcreator2',
                  openseaVerificationStatus: 'verified',
                },
              ],
            });

          await controller.detectNfts(['0x1']);

          // Expect to be called twice
          expect(mockAddNft).toHaveBeenNthCalledWith(
            1,
            '0xtest1',
            '2574',
            'mainnet',
            {
              nftMetadata: {
                description: 'Description 2574',
                image: 'image/2574.png',
                name: 'ID 2574',
                standard: 'ERC721',
                imageOriginal: 'imageOriginal/2574.png',
                collection: {
                  id: '0xtest1',
                  contractDeployedAt: undefined,
                  creator: '0xcreator1',
                  openseaVerificationStatus: 'verified',
                  ownerCount: undefined,
                  tokenCount: undefined,
                  topBid: testTopBid,
                },
                chainId: 1,
              },
              userAddress: selectedAccount.address,
              source: Source.Detected,
            },
          );
          expect(mockAddNft).toHaveBeenNthCalledWith(
            2,
            '0xtest2',
            '2575',
            'mainnet',
            {
              nftMetadata: {
                description: 'Description 2575',
                image: 'image/2575.png',
                name: 'ID 2575',
                standard: 'ERC721',
                imageOriginal: 'imageOriginal/2575.png',
                collection: {
                  id: '0xtest2',
                  contractDeployedAt: undefined,
                  creator: '0xcreator2',
                  openseaVerificationStatus: 'verified',
                  ownerCount: undefined,
                  tokenCount: undefined,
                },
                chainId: 1,
              },
              userAddress: selectedAccount.address,
              source: Source.Detected,
            },
          );
        },
      );
    });
    it('should detect and add NFTs and filter them correctly', async () => {
      const mockAddNft = jest.fn();
      const selectedAddress = '0x12345';
      const selectedAccount = createMockInternalAccount({
        address: selectedAddress,
      });
      const mockGetSelectedAccount = jest.fn().mockReturnValue(selectedAccount);
      await withController(
        {
          options: { addNft: mockAddNft },
          mockPreferencesState: {},
          mockGetSelectedAccount,
        },
        async ({ controller, controllerEvents }) => {
          controllerEvents.triggerPreferencesStateChange({
            ...getDefaultPreferencesState(),
            useNftDetection: true,
          });
          // Wait for detect call triggered by preferences state change to settle
          await advanceTime({
            clock,
            duration: 1,
          });
          mockAddNft.mockReset();

          nock(NFT_API_BASE_URL)
            .get(
              `/collections?contract=0xtestCollection1&contract=0xtestCollection2&chainId=1`,
            )
            .reply(200, {
              collections: [
                {
                  chainId: 1,
                  id: '0xtestCollection1',
                  creator: '0xcreator1',
                  openseaVerificationStatus: 'verified',
                },
                {
                  chainId: 1,
                  id: '0xtestCollection2',
                  creator: '0xcreator2',
                  openseaVerificationStatus: 'verified',
                },
              ],
            });

          await controller.detectNfts(['0x1']);

          expect(mockAddNft).toHaveBeenCalledTimes(2);
          // In this test we mocked that reservoir returned 5 NFTs
          // the only NFTs we want to add are when isSpam=== false and (either no blockaid result returned or blockaid says "Benign")
          expect(mockAddNft).toHaveBeenNthCalledWith(
            1,
            '0xtestCollection1',
            '1',
            'mainnet',
            {
              nftMetadata: {
                description: 'Description 1',
                image: 'image/1.png',
                name: 'ID 1',
                standard: 'ERC721',
                imageOriginal: 'imageOriginal/1.png',
                collection: {
                  id: '0xtestCollection1',
                  contractDeployedAt: undefined,
                  creator: '0xcreator1',
                  openseaVerificationStatus: 'verified',
                  ownerCount: undefined,
                  tokenCount: undefined,
                },
                chainId: 1,
              },
              userAddress: selectedAccount.address,
              source: Source.Detected,
            },
          );
          expect(mockAddNft).toHaveBeenNthCalledWith(
            2,
            '0xtestCollection2',
            '2',
            'mainnet',
            {
              nftMetadata: {
                description: 'Description 2',
                image: 'image/2.png',
                name: 'ID 2',
                standard: 'ERC721',
                imageOriginal: 'imageOriginal/2.png',
                collection: {
                  id: '0xtestCollection2',
                  contractDeployedAt: undefined,
                  creator: '0xcreator2',
                  openseaVerificationStatus: 'verified',
                  ownerCount: undefined,
                  tokenCount: undefined,
                },
                chainId: 1,
              },
              userAddress: selectedAccount.address,
              source: Source.Detected,
            },
          );
        },
      );
    });

    it('should detect and add NFTs from a single collection', async () => {
      const mockAddNft = jest.fn();
      const selectedAddress = 'Oxuser';
      const selectedAccount = createMockInternalAccount({
        address: selectedAddress,
      });
      const mockGetSelectedAccount = jest.fn().mockReturnValue(selectedAccount);
      await withController(
        {
          options: { addNft: mockAddNft },
          mockPreferencesState: {},
          mockGetSelectedAccount,
        },
        async ({ controller, controllerEvents }) => {
          controllerEvents.triggerPreferencesStateChange({
            ...getDefaultPreferencesState(),
            useNftDetection: true,
          });
          // Wait for detect call triggered by preferences state change to settle
          await advanceTime({
            clock,
            duration: 1,
          });
          mockAddNft.mockReset();
          nock(NFT_API_BASE_URL)
            .get(
              `/users/${selectedAddress}/tokens?chainIds=1&limit=50&includeTopBid=true&continuation=`,
            )
            .reply(200, {
              tokens: [
                {
                  token: {
                    chainId: 1,
                    contract: '0xtestCollection1',
                    kind: 'erc721',
                    name: 'ID 1',
                    description: 'Description 1',
                    image: 'image/1.png',
                    tokenId: '1',
                    metadata: {
                      imageOriginal: 'imageOriginal/1.png',
                      imageMimeType: 'image/png',
                      tokenURI: 'tokenURITest',
                    },
                    isSpam: false,
                    collection: {
                      id: '0xtestCollection1',
                    },
                  },
                  blockaidResult: {
                    // TODO: Either fix this lint violation or explain why it's necessary to ignore.
                    // eslint-disable-next-line @typescript-eslint/naming-convention
                    result_type: BlockaidResultType.Benign,
                  },
                },
                {
                  token: {
                    chainId: 1,
                    contract: '0xtestCollection1',
                    kind: 'erc721',
                    name: 'ID 2',
                    description: 'Description 2',
                    image: 'image/2.png',
                    tokenId: '2',
                    metadata: {
                      imageOriginal: 'imageOriginal/2.png',
                      imageMimeType: 'image/png',
                      tokenURI: 'tokenURITest',
                    },
                    isSpam: false,
                    collection: {
                      id: '0xtestCollection1',
                    },
                  },
                },
              ],
            });

          nock(NFT_API_BASE_URL)
            .get(`/collections?contract=0xtestCollection1&chainId=1`)
            .reply(200, {
              collections: [
                {
                  id: '0xtestCollection1',
                  chainId: 1,
                  creator: '0xcreator1',
                  openseaVerificationStatus: 'verified',
                  ownerCount: '555',
                },
              ],
            });

          await controller.detectNfts(['0x1']);

          expect(mockAddNft).toHaveBeenCalledTimes(2);
          // In this test we mocked that reservoir returned 5 NFTs
          // the only NFTs we want to add are when isSpam=== false and (either no blockaid result returned or blockaid says "Benign")
          expect(mockAddNft).toHaveBeenNthCalledWith(
            1,
            '0xtestCollection1',
            '1',
            'mainnet',
            {
              nftMetadata: {
                description: 'Description 1',
                image: 'image/1.png',
                name: 'ID 1',
                standard: 'ERC721',
                imageOriginal: 'imageOriginal/1.png',
                collection: {
                  id: '0xtestCollection1',
                  contractDeployedAt: undefined,
                  creator: '0xcreator1',
                  openseaVerificationStatus: 'verified',
                  ownerCount: '555',
                  tokenCount: undefined,
                },
                chainId: 1,
              },
              userAddress: selectedAccount.address,
              source: Source.Detected,
            },
          );
          expect(mockAddNft).toHaveBeenNthCalledWith(
            2,
            '0xtestCollection1',
            '2',
            'mainnet',
            {
              nftMetadata: {
                description: 'Description 2',
                image: 'image/2.png',
                name: 'ID 2',
                standard: 'ERC721',
                imageOriginal: 'imageOriginal/2.png',
                collection: {
                  id: '0xtestCollection1',
                  contractDeployedAt: undefined,
                  creator: '0xcreator1',
                  openseaVerificationStatus: 'verified',
                  ownerCount: '555',
                  tokenCount: undefined,
                },
                chainId: 1,
              },
              userAddress: selectedAccount.address,
              source: Source.Detected,
            },
          );
        },
      );
    });

    it('does not error when NFT token metadata is null', async () => {
      const mockAddNft = jest.fn();
      const selectedAddress = 'Oxuser';
      const selectedAccount = createMockInternalAccount({
        address: selectedAddress,
      });
      const mockGetSelectedAccount = jest.fn().mockReturnValue(selectedAccount);
      await withController(
        {
          options: { addNft: mockAddNft },
          mockPreferencesState: {},
          mockGetSelectedAccount,
        },
        async ({ controller, controllerEvents }) => {
          controllerEvents.triggerPreferencesStateChange({
            ...getDefaultPreferencesState(),
            useNftDetection: true,
          });
          // Wait for detect call triggered by preferences state change to settle
          await advanceTime({
            clock,
            duration: 1,
          });
          mockAddNft.mockReset();
          nock(NFT_API_BASE_URL)
            .get(
              `/users/${selectedAddress}/tokens?chainIds=1&limit=50&includeTopBid=true&continuation=`,
            )
            .reply(200, {
              tokens: [
                {
                  token: {
                    chainId: 1,
                    contract: '0xtestCollection1',
                    kind: 'erc721',
                    name: 'ID 1',
                    description: 'Description 1',
                    image: 'image/1.png',
                    tokenId: '1',
                    metadata: null,
                    isSpam: false,
                    collection: {
                      id: '0xtestCollection1',
                    },
                  },
                  blockaidResult: {
                    // TODO: Either fix this lint violation or explain why it's necessary to ignore.
                    // eslint-disable-next-line @typescript-eslint/naming-convention
                    result_type: BlockaidResultType.Benign,
                  },
                },
              ],
            });

          nock(NFT_API_BASE_URL)
            .get(`/collections?contract=0xtestCollection1&chainId=1`)
            .reply(200, {
              collections: [
                {
                  chainId: 1,
                  id: '0xtestCollection1',
                  creator: '0xcreator1',
                  openseaVerificationStatus: 'verified',
                  ownerCount: '555',
                },
              ],
            });

          await controller.detectNfts(['0x1']);

          expect(mockAddNft).toHaveBeenCalledTimes(1);
          expect(mockAddNft).toHaveBeenNthCalledWith(
            1,
            '0xtestCollection1',
            '1',
            'mainnet',
            {
              nftMetadata: {
                chainId: 1,
                description: 'Description 1',
                image: 'image/1.png',
                name: 'ID 1',
                standard: 'ERC721',
                collection: {
                  id: '0xtestCollection1',
                  contractDeployedAt: undefined,
                  creator: '0xcreator1',
                  openseaVerificationStatus: 'verified',
                  ownerCount: '555',
                  topBid: undefined,
                },
              },
              userAddress: selectedAccount.address,
              source: Source.Detected,
            },
          );
        },
      );
    });

    it('should add collection information correctly when a single batch fails to get collection informations', async () => {
      // Mock that MAX_GET_COLLECTION_BATCH_SIZE is equal 1 instead of 20
      Object.defineProperty(constants, 'MAX_GET_COLLECTION_BATCH_SIZE', {
        value: 1,
      });
      expect(MAX_GET_COLLECTION_BATCH_SIZE).toBe(1);
      const mockAddNft = jest.fn();
      const selectedAddress = '0x123';
      const selectedAccount = createMockInternalAccount({
        address: selectedAddress,
      });
      const mockGetSelectedAccount = jest.fn().mockReturnValue(selectedAccount);
      await withController(
        {
          options: { addNft: mockAddNft },
          mockPreferencesState: {},
          mockGetSelectedAccount,
        },
        async ({ controller, controllerEvents }) => {
          controllerEvents.triggerPreferencesStateChange({
            ...getDefaultPreferencesState(),
            useNftDetection: true,
          });
          // Wait for detect call triggered by preferences state change to settle
          await advanceTime({
            clock,
            duration: 1,
          });
          mockAddNft.mockReset();

          nock(NFT_API_BASE_URL)
            .get(`/collections?contract=0xtest1&chainId=1`)
            .reply(200, {
              collections: [
                {
                  chainId: 1,
                  id: '0xtest1',
                  creator: '0xcreator1',
                  openseaVerificationStatus: 'verified',
                },
              ],
            });

          nock(NFT_API_BASE_URL)
            .get(`/collections?contract=0xtest2&chainId=1`)
            .replyWithError(new Error('Failed to fetch'));

          await controller.detectNfts(['0x1']);

          // Expect to be called twice
          expect(mockAddNft).toHaveBeenNthCalledWith(
            1,
            '0xtest1',
            '2574',
            'mainnet',
            {
              nftMetadata: {
                description: 'Description 2574',
                image: 'image/2574.png',
                name: 'ID 2574',
                standard: 'ERC721',
                imageOriginal: 'imageOriginal/2574.png',
                collection: {
                  id: '0xtest1',
                  contractDeployedAt: undefined,
                  creator: '0xcreator1',
                  openseaVerificationStatus: 'verified',
                  ownerCount: undefined,
                  tokenCount: undefined,
                },
                chainId: 1,
              },
              userAddress: selectedAccount.address,
              source: Source.Detected,
            },
          );
          expect(mockAddNft).toHaveBeenNthCalledWith(
            2,
            '0xtest2',
            '2575',
            'mainnet',
            {
              nftMetadata: {
                description: 'Description 2575',
                image: 'image/2575.png',
                name: 'ID 2575',
                standard: 'ERC721',
                imageOriginal: 'imageOriginal/2575.png',
                collection: {
                  id: '0xtest2',
                },
                chainId: 1,
              },
              userAddress: selectedAccount.address,
              source: Source.Detected,
            },
          );

          Object.defineProperty(constants, 'MAX_GET_COLLECTION_BATCH_SIZE', {
            value: 20,
          });
          expect(MAX_GET_COLLECTION_BATCH_SIZE).toBe(20);
        },
      );
    });
  });

  it('should detect and add NFTs by networkClientId correctly', async () => {
    const mockAddNft = jest.fn();
    const mockGetSelectedAccount = jest.fn();
    await withController(
      {
        options: {
          addNft: mockAddNft,
        },
        mockGetSelectedAccount,
      },
      async ({ controller, controllerEvents }) => {
        const selectedAddress = '0x1';
        const updatedSelectedAccount = createMockInternalAccount({
          address: selectedAddress,
        });
        mockGetSelectedAccount.mockReturnValue(updatedSelectedAccount);
        controllerEvents.triggerPreferencesStateChange({
          ...getDefaultPreferencesState(),
          useNftDetection: true,
        });
        // Wait for detect call triggered by preferences state change to settle
        await advanceTime({
          clock,
          duration: 1,
        });
        mockAddNft.mockReset();
        nock(NFT_API_BASE_URL)
          .get(
            `/collections?contract=0xebE4e5E773AFD2bAc25De0cFafa084CFb3cBf1eD&chainId=1`,
          )
          .replyWithError(new Error('Failed to fetch'));

        await controller.detectNfts(['0x1'], {
          userAddress: '0x9',
        });

        expect(mockAddNft).toHaveBeenCalledWith(
          '0xebE4e5E773AFD2bAc25De0cFafa084CFb3cBf1eD',
          '2574',
          'mainnet',
          {
            nftMetadata: {
              description: 'Description 2574',
              image: 'image/2574.png',
              name: 'ID 2574',
              standard: 'ERC721',
              imageOriginal: 'imageOriginal/2574.png',
              chainId: 1,
            },
            userAddress: '0x9',
            source: Source.Detected,
          },
        );
      },
    );
  });

  it('should not detect NFTs that exist in the ignoreList', async () => {
    const mockAddNft = jest.fn();
    const mockGetSelectedAccount = jest.fn();
    const mockGetNftState = jest.fn().mockImplementation(() => {
      return {
        ...getDefaultNftControllerState(),
        ignoredNfts: [
          // This address and token ID are always detected, as determined by
          // the nock mocks setup in `beforeEach`
          // TODO: Migrate nock setup into individual tests
          {
            address: '0xebE4e5E773AFD2bAc25De0cFafa084CFb3cBf1eD',
            tokenId: '2574',
          },
        ],
      };
    });
    const selectedAddress = '0x9';
    const selectedAccount = createMockInternalAccount({
      address: selectedAddress,
    });
    await withController(
      {
        options: { addNft: mockAddNft, getNftState: mockGetNftState },
        mockPreferencesState: { selectedAddress },
        mockGetSelectedAccount,
      },
      async ({ controller, controllerEvents }) => {
        mockGetSelectedAccount.mockReturnValue(selectedAccount);
        controllerEvents.triggerPreferencesStateChange({
          ...getDefaultPreferencesState(),
          useNftDetection: true,
        });
        // Wait for detect call triggered by preferences state change to settle
        await advanceTime({
          clock,
          duration: 1,
        });
        mockAddNft.mockReset();

        nock(NFT_API_BASE_URL)
          .get(
            `/collections?contract=0xebE4e5E773AFD2bAc25De0cFafa084CFb3cBf1eD&chainId=1`,
          )
          .replyWithError(new Error('Failed to fetch'));

        await controller.detectNfts(['0x1']);

        expect(mockAddNft).not.toHaveBeenCalled();
      },
    );
  });

  it('should not detect and add NFTs if there is no selectedAddress', async () => {
    const mockAddNft = jest.fn();
    // mock uninitialised selectedAccount when it is ''
    const mockGetSelectedAccount = jest.fn().mockReturnValue({ address: '' });
    await withController(
      {
        options: { addNft: mockAddNft },
        mockPreferencesState: {},
        mockGetSelectedAccount,
      },
      async ({ controller, controllerEvents }) => {
        controllerEvents.triggerPreferencesStateChange({
          ...getDefaultPreferencesState(),
          useNftDetection: true, // auto-detect is enabled so it proceeds to check userAddress
        });

        await controller.detectNfts(['0x1']);

        expect(mockAddNft).not.toHaveBeenCalled();
      },
    );
  });

  it('should return true if mainnet is detected', async () => {
    const mockAddNft = jest.fn();
    const provider = new FakeProvider();
    const mockNetworkClient: NetworkClient = {
      configuration: {
        chainId: ChainId.mainnet,
        rpcUrl: 'https://test.network',
        failoverRpcUrls: [],
        ticker: 'TEST',
        type: NetworkClientType.Custom,
      },
      provider,
      blockTracker: new FakeBlockTracker({ provider }),
      destroy: () => {
        // do nothing
      },
    };
    await withController(
      { options: { addNft: mockAddNft } },
      async ({ controller }) => {
        const result = controller.isMainnetByNetworkClientId(mockNetworkClient);
        expect(result).toBe(true);
      },
    );
  });

  it('should not detectNfts when disabled is false and useNftDetection is true', async () => {
    await withController(
      { options: { disabled: false } },
      async ({ controller, controllerEvents }) => {
        const mockNfts = sinon.stub(controller, 'detectNfts');
        controllerEvents.triggerPreferencesStateChange({
          ...getDefaultPreferencesState(),
          useNftDetection: true,
        });
        // Wait for detect call triggered by preferences state change to settle
        await advanceTime({
          clock,
          duration: 1,
        });

        expect(mockNfts.calledOnce).toBe(false);
      },
    );
  });

  it('should not detect and add NFTs if preferences controller useNftDetection is set to false', async () => {
    const mockAddNft = jest.fn();
    const mockGetSelectedAccount = jest.fn();
    const selectedAddress = '0x9';
    const selectedAccount = createMockInternalAccount({
      address: selectedAddress,
    });
    await withController(
      {
        options: { addNft: mockAddNft, disabled: false },
        mockPreferencesState: {},
        mockGetSelectedAccount,
      },
      async ({ controller, controllerEvents }) => {
        mockGetSelectedAccount.mockReturnValue(selectedAccount);
        controllerEvents.triggerPreferencesStateChange({
          ...getDefaultPreferencesState(),
          useNftDetection: false,
        });
        // Wait for detect call triggered by preferences state change to settle
        await advanceTime({
          clock,
          duration: 1,
        });
        mockAddNft.mockReset();

        await controller.detectNfts(['0x1']);

        expect(mockAddNft).not.toHaveBeenCalled();
      },
    );
  });

  it('should not call addNFt when the request to Nft API call throws', async () => {
    const selectedAccount = createMockInternalAccount({ address: '0x3' });
    nock(NFT_API_BASE_URL)
      // ESLint is confused; this is a string.
      // eslint-disable-next-line @typescript-eslint/restrict-template-expressions
      .get(`/users/${selectedAccount.address}/tokens`)
      .query({
        continuation: '',
        limit: '50',
        chainIds: '1',
        includeTopBid: true,
      })
      .replyWithError(new Error('Failed to fetch'))
      .persist();
    const mockAddNft = jest.fn();
    const mockGetSelectedAccount = jest.fn().mockReturnValue(selectedAccount);
    await withController(
      {
        options: {
          addNft: mockAddNft,
        },
        mockGetSelectedAccount,
      },
      async ({ controller, controllerEvents }) => {
        controllerEvents.triggerPreferencesStateChange({
          ...getDefaultPreferencesState(),
          useNftDetection: true,
        });
        // Wait for detect call triggered by preferences state change to settle
        await advanceTime({
          clock,
          duration: 1,
        });
        mockAddNft.mockReset();

        // eslint-disable-next-line jest/require-to-throw-message
        await expect(() => controller.detectNfts(['0x1'])).rejects.toThrow();

        expect(mockAddNft).not.toHaveBeenCalled();
      },
    );
  });

  it('should rethrow error when Nft APi server fails with error other than fetch failure', async () => {
    const selectedAddress = '0x4';
    const selectedAccount = createMockInternalAccount({
      address: selectedAddress,
    });
    const mockGetSelectedAccount = jest.fn().mockReturnValue(selectedAccount);
    await withController(
      { mockPreferencesState: {}, mockGetSelectedAccount },
      async ({ controller, controllerEvents }) => {
        controllerEvents.triggerPreferencesStateChange({
          ...getDefaultPreferencesState(),
          useNftDetection: true,
        });
        // Wait for detect call triggered by preferences state change to settle
        await advanceTime({
          clock,
          duration: 1,
        });
        // This mock is for the call under test
        nock(NFT_API_BASE_URL)
          .get(`/users/${selectedAddress}/tokens`)
          .query({
            continuation: '',
            limit: '50',
            chainIds: '1',
            includeTopBid: true,
          })
          .replyWithError(new Error('UNEXPECTED ERROR'));

        await expect(() => controller.detectNfts(['0x1'])).rejects.toThrow(
          'UNEXPECTED ERROR',
        );
      },
    );
  });

  it('should rethrow error when attempt to add NFT fails', async () => {
    const mockAddNft = jest.fn();
    const mockGetSelectedAccount = jest.fn();
    const selectedAddress = '0x1';
    const selectedAccount = createMockInternalAccount({
      address: selectedAddress,
    });
    await withController(
      {
        options: { addNft: mockAddNft },
        mockPreferencesState: {},
        mockGetSelectedAccount,
      },
      async ({ controller, controllerEvents }) => {
        mockGetSelectedAccount.mockReturnValue(selectedAccount);
        controllerEvents.triggerPreferencesStateChange({
          ...getDefaultPreferencesState(),
          useNftDetection: true,
        });
        // Wait for detect call triggered by preferences state change to settle
        await advanceTime({
          clock,
          duration: 1,
        });
        mockAddNft.mockReset();
        mockAddNft.mockRejectedValueOnce(new Error('UNEXPECTED ERROR'));

        nock(NFT_API_BASE_URL)
          .get(
            `/collections?contract=0xCE7ec4B2DfB30eB6c0BB5656D33aAd6BFb4001Fc&contract=0x0B0fa4fF58D28A88d63235bd0756EDca69e49e6d&contract=0xebE4e5E773AFD2bAc25De0cFafa084CFb3cBf1eD&chainId=1`,
          )
          .replyWithError(new Error('Failed to fetch'));

        await expect(
          async () => await controller.detectNfts(['0x1']),
        ).rejects.toThrow('UNEXPECTED ERROR');
      },
    );
  });

  it('should not call detectNfts when settings change', async () => {
    const mockGetSelectedAccount = jest
      .fn()
      .mockReturnValue(defaultSelectedAccount);
    await withController(
      {
        options: {},
        mockGetSelectedAccount,
      },
      async ({ controller, controllerEvents }) => {
        const detectNfts = sinon.stub(controller, 'detectNfts');

        // Repeated preference changes should only trigger 1 detection
        for (let i = 0; i < 5; i++) {
          controllerEvents.triggerPreferencesStateChange({
            ...getDefaultPreferencesState(),
            useNftDetection: true,
            securityAlertsEnabled: true,
          });
        }
        await advanceTime({ clock, duration: 1 });
        expect(detectNfts.callCount).toBe(0);

        // Irrelevant preference changes shouldn't trigger a detection
        controllerEvents.triggerPreferencesStateChange({
          ...getDefaultPreferencesState(),
          useNftDetection: true,
          securityAlertsEnabled: true,
        });
        await advanceTime({ clock, duration: 1 });
        expect(detectNfts.callCount).toBe(0);
      },
    );
  });

  it('should only updates once when detectNfts called twice', async () => {
    const mockAddNft = jest.fn();
    const mockGetSelectedAccount = jest.fn();
    const selectedAddress = '0x9';
    const selectedAccount = createMockInternalAccount({
      address: selectedAddress,
    });
    await withController(
      {
        options: { addNft: mockAddNft, disabled: false },
        mockPreferencesState: {},
        mockGetSelectedAccount,
      },
      async ({ controller, controllerEvents }) => {
        mockGetSelectedAccount.mockReturnValue(selectedAccount);
        controllerEvents.triggerPreferencesStateChange({
          ...getDefaultPreferencesState(),
          useNftDetection: true,
        });

        nock(NFT_API_BASE_URL)
          .get(
            `/collections?contract=0xebE4e5E773AFD2bAc25De0cFafa084CFb3cBf1eD&chainId=1`,
          )
          .replyWithError(new Error('Failed to fetch'));
        await Promise.all([
          controller.detectNfts(['0x1']),
          controller.detectNfts(['0x1']),
        ]);

        expect(mockAddNft).toHaveBeenCalledTimes(1);
      },
    );
  });
});

/**
 * A collection of mock external controller events.
 */
type ControllerEvents = {
  triggerPreferencesStateChange: (state: PreferencesState) => void;
  triggerNetworkStateChange: (state: NetworkState) => void;
};

type WithControllerCallback<ReturnValue> = ({
  controller,
}: {
  controller: NftDetectionController;
  controllerEvents: ControllerEvents;
}) => Promise<ReturnValue> | ReturnValue;

type WithControllerOptions = {
  options?: Partial<ConstructorParameters<typeof NftDetectionController>[0]>;
  mockNetworkClientConfigurationsByNetworkClientId?: Record<
    NetworkClientId,
    NetworkClientConfiguration
  >;
  mockNetworkState?: Partial<NetworkState>;
  mockPreferencesState?: Partial<PreferencesState>;
  mockGetSelectedAccount?: jest.Mock<AccountsController['getSelectedAccount']>;
  mockFindNetworkClientIdByChainId?: jest.Mock<
    NetworkController['findNetworkClientIdByChainId']
  >;
};

type WithControllerArgs<ReturnValue> =
  | [WithControllerCallback<ReturnValue>]
  | [WithControllerOptions, WithControllerCallback<ReturnValue>];

/**
 * Builds a controller based on the given options, and calls the given function
 * with that controller.
 *
 * @param args - Either a function, or an options bag + a function. The options
 * bag accepts controller options and config; the function
 * will be called with the built controller.
 * @returns Whatever the callback returns.
 */
async function withController<ReturnValue>(
  ...args: WithControllerArgs<ReturnValue>
): Promise<ReturnValue> {
  const [
    {
      options = {},
      mockNetworkClientConfigurationsByNetworkClientId = {},
      mockFindNetworkClientIdByChainId = {},
      mockNetworkState = {},
      mockPreferencesState = {},
      mockGetSelectedAccount = jest
        .fn()
        .mockReturnValue(defaultSelectedAccount),
    },
    testFunction,
  ] = args.length === 2 ? args : [{}, args[0]];

  const messenger = new Messenger<AllowedActions, AllowedEvents>();

  messenger.registerActionHandler(
    'NetworkController:getState',
    jest.fn<NetworkState, []>().mockReturnValue({
      ...getDefaultNetworkControllerState(),
      ...mockNetworkState,
    }),
  );

  messenger.registerActionHandler(
    'AccountsController:getSelectedAccount',
    mockGetSelectedAccount,
  );

  const getNetworkClientById = buildMockGetNetworkClientById(
    mockNetworkClientConfigurationsByNetworkClientId,
  );
  const findNetworkClientIdByChainId = buildMockFindNetworkClientIdByChainId(
    mockFindNetworkClientIdByChainId,
  );

  messenger.registerActionHandler(
    'NetworkController:getNetworkClientById',
    getNetworkClientById,
  );

  messenger.registerActionHandler(
    'NetworkController:findNetworkClientIdByChainId',
    findNetworkClientIdByChainId,
  );

  messenger.registerActionHandler(
    'PreferencesController:getState',
    jest.fn<PreferencesState, []>().mockReturnValue({
      ...getDefaultPreferencesState(),
      ...mockPreferencesState,
    }),
  );

  const controller = new NftDetectionController({
    messenger: messenger.getRestricted({
      name: controllerName,
      allowedActions: [
        'NetworkController:getState',
        'NetworkController:getNetworkClientById',
        'PreferencesController:getState',
        'AccountsController:getSelectedAccount',
        'NetworkController:findNetworkClientIdByChainId',
      ],
      allowedEvents: [
        'NetworkController:stateChange',
        'PreferencesController:stateChange',
      ],
    }),
    disabled: true,
    addNft: jest.fn(),
    getNftState: getDefaultNftControllerState,
    ...options,
  });

  const controllerEvents = {
    triggerPreferencesStateChange: (state: PreferencesState) => {
      messenger.publish('PreferencesController:stateChange', state, []);
    },
    triggerNetworkStateChange: (state: NetworkState) => {
      messenger.publish('NetworkController:stateChange', state, []);
    },
  };

  return await testFunction({
    controller,
    controllerEvents,
  });
}

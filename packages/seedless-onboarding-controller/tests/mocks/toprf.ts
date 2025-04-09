import { utf8ToBytes } from '@noble/ciphers/utils';

import { MockToprfEncryptorDecryptor } from './encryption';

export const TOPRF_BASE_URL = /https:\/\/node-[1-5]\.dev-node\.web3auth\.io/u;

export const MOCK_TOPRF_COMMITMENT_RESPONSE = {
  jsonrpc: '2.0',
  result: {
    authToken:
      '{"data":"fe6566a930f9493deba5abb2c222200d1ac20a47a768007364366e1231f419133c7900d2ec673c91149e6acfb7a1b0c88d3fe48b464805800335958551f3f934706b814a4ed985e29f12b4793a18d78b2d1dd94889c072180ebfc55b97923f6fc8b601c27e8ff830ac06d137592769faf5322e1c0863ec587740c7f252e2321006a42fed075450748e258f5b6ae12cb9d29fa185eb14642c26af97839bbaa0485373ed2d005b06223e0d63145f92bb235abb3aa68e88549729639b094f464e95ec6e6fa519c62814ebcf2687b070efd018b244db5c4f8e2b34efb990d310a4efd6b179655f6eacfb1afde439ac70e67ff42a3b548cd5b8605fc5845bfb08a87ee2bf9461556bd97f572fa3f6aa9de65c91becd291bfd25c65807eae690e7cc4290bab083f2178de2468a95b080a722e064561e20df55de56dde09547e1ce9221603c8d4b405b97e51aadb627ce430a77941fff23b46dde9353fbdd847b0deba29d4a30007bf8e1f432980b969f1cf4f2100a2372f0d65ea2242c0ac8617ddb57617dfe98c748269af7e6220d364883ff53b6a6bff59092f808e764cc7daf5f85f0c8f65ec99183a097cc99fd5fc6412fdfdca38a9fe9fe1f7530550960904d06127085d79164c142a0a7ac37ab265773beda596dc6a73692b84bea089cf8af15663bb05b705779e74705fc3906227d82","metadata":{"iv":"6002038ab67001f33889a11b656f7082","ephemPublicKey":"04d612eae53509c5dc94c036f82b8878b45395edde31878c2def115911febd5dc3e8ef178cdc43b6982a74a93d2c4b234c6516c9a2a497497d1527abaea377baef","mac":"f61e95b44e261119fc9525a57d10618a876767c3f0a8c6fbf21f7ba60b3f8acb","mode":"AES256"}}',
    nodeIndex: 1,
    pubKey: '',
    keyIndex: 0,
    nodePubKey:
      '04f74389b0a4c8d10d2a687ae575f69b20f412d41ab7f1fe6b358aa1487132724754e3a73098ed9bced3ef8821736e9794f9264a1420c0c7ad15d2fa617ba35ef7',
  },
  id: 10,
};

export const MOCK_TOPRF_AUTHENTICATION_RESPONSE = {
  jsonrpc: '2.0',
  result: {
    signature:
      '28a045eb66bf92519e37955c62481638d2e5b7108b057eb9d3a7a0661e2b5542480633c90ef17d703c360c73a4b1542a51c381c7d4b89e2a46e2ebfb9f680aab1b',
    data: 'mug00\x1C76a7015c9096cc0f1550b6bcc87c27b3f050bbc821932f36b6447343b33a9d8f\x1C45496d141b2d1f9f88e5ec0a7a9f160b00d0ac755ee6b605f5ba8e55cd6bfaa8\x1C78dc55721c770edef33e7f2bdbec712bc6fe3894464f7eb16d902fac3df6c6\x1Ctorus-test-health\x1C1744021816',
    nodePubX:
      'f74389b0a4c8d10d2a687ae575f69b20f412d41ab7f1fe6b358aa14871327247',
    nodePubY:
      '54e3a73098ed9bced3ef8821736e9794f9264a1420c0c7ad15d2fa617ba35ef7',
    nodeIndex: '1',
  },
  id: 10,
};

export const MOCK_SECRET_DATA_ADD_RESPONSE = {
  success: true,
  message: 'Updated successfully',
};

export const MOCK_SECRET_DATA_GET_RESPONSE = {
  success: true,
  data: [],
};

/**
 * Creates a mock secret data get response
 *
 * @param secretDataArr - The data to be returned
 * @param password - The password to be used
 * @returns The mock secret data get response
 */
export function createMockSecretDataGetResponse<
  T extends Uint8Array | { seedPhrase: Uint8Array; timestamp: number },
>(secretDataArr: T[], password: string) {
  const mockToprfEncryptor = new MockToprfEncryptorDecryptor();

  const encryptedSecretData = secretDataArr.map((secretData) => {
    let b64SecretData: string;
    let timestamp = Date.now();
    if (secretData instanceof Uint8Array) {
      b64SecretData = Buffer.from(secretData).toString('base64');
    } else {
      b64SecretData = Buffer.from(secretData.seedPhrase).toString('base64');
      timestamp = secretData.timestamp;
    }

    const metadata = JSON.stringify({
      seedPhrase: b64SecretData,
      timestamp,
    });

    return mockToprfEncryptor.encrypt(
      mockToprfEncryptor.keyFromPassword(password),
      utf8ToBytes(metadata),
    );
  });

  const jsonData = {
    success: true,
    data: encryptedSecretData,
  };

  return jsonData;
}

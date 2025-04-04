export const MOCK_AUTH_SET_URL =
  'https://mock-simple-auth.sapphire-dev-2-1.authnetwork.dev/auth/set';
export const MOCK_AUTH_GET_URL =
  'https://mock-simple-auth.sapphire-dev-2-1.authnetwork.dev/auth/get';
export const MOCK_METADATA_SET_URL =
  'https://mock-simple-auth.sapphire-dev-2-1.authnetwork.dev/metadata/set';
export const MOCK_METADATA_GET_URL =
  'https://mock-simple-auth.sapphire-dev-2-1.authnetwork.dev/metadata/get';

export const MOCK_AUTH_SET_RESPONSE = {
  success: true,
  key: 'mock-key',
};

export const MOCK_AUTH_GET_RESPONSE = {
  success: true,
  message: JSON.stringify({
    nodeAuthTokens: ['mock-node-auth-token'],
    hasValidEncKey: false,
  }),
};

export const MOCK_METADATA_SET_RESPONSE = {
  success: true,
  key: 'mock-key',
};

export const MOCK_METADATA_GET_RESPONSE = {
  success: true,
  message: 'MOCK_DATA',
};

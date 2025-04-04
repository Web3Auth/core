import nock from 'nock';

import {
  MOCK_AUTH_GET_RESPONSE,
  MOCK_AUTH_GET_URL,
  MOCK_AUTH_SET_RESPONSE,
  MOCK_AUTH_SET_URL,
  MOCK_METADATA_GET_RESPONSE,
  MOCK_METADATA_GET_URL,
  MOCK_METADATA_SET_RESPONSE,
  MOCK_METADATA_SET_URL,
} from '../mocks/metadataStore';

type MockReply = {
  status: nock.StatusCode;
  body?: nock.Body;
};

export const handleMockAuthSet = (mockReply?: MockReply) => {
  const reply = mockReply ?? {
    status: 200,
    body: MOCK_AUTH_SET_RESPONSE,
  };
  const mockEndpoint = nock(MOCK_AUTH_SET_URL)
    .persist()
    .post('')
    .reply(reply.status, reply.body);

  return mockEndpoint;
};

export const handleMockAuthGet = (mockReply?: MockReply) => {
  const reply = mockReply ?? {
    status: 200,
    body: MOCK_AUTH_GET_RESPONSE,
  };

  const mockEndpoint = nock(MOCK_AUTH_GET_URL)
    .persist()
    .post('')
    .reply(reply.status, reply.body);

  return mockEndpoint;
};

export const handleMockMetadataSet = (mockReply?: MockReply) => {
  const reply = mockReply ?? {
    status: 200,
    body: MOCK_METADATA_SET_RESPONSE,
  };
  const mockEndpoint = nock(MOCK_METADATA_SET_URL)
    .post('')
    .reply(reply.status, reply.body);

  return mockEndpoint;
};

export const handleMockMetadataGet = (mockReply?: MockReply) => {
  const reply = mockReply ?? {
    status: 200,
    body: MOCK_METADATA_GET_RESPONSE,
  };
  const mockEndpoint = nock(MOCK_METADATA_GET_URL)
    .post('')
    .reply(reply.status, reply.body);

  return mockEndpoint;
};

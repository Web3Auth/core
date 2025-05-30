import { Caip25EndowmentPermissionName } from '@metamask/chain-agnostic-permission';
import {
  PermissionDoesNotExistError,
  UnrecognizedSubjectError,
} from '@metamask/permission-controller';
import { rpcErrors } from '@metamask/rpc-errors';
import type { JsonRpcRequest } from '@metamask/utils';

import { walletRevokeSession } from './wallet-revokeSession';

const baseRequest: JsonRpcRequest & { origin: string } = {
  origin: 'http://test.com',
  params: {},
  jsonrpc: '2.0' as const,
  id: 1,
  method: 'wallet_revokeSession',
};

const createMockedHandler = () => {
  const next = jest.fn();
  const end = jest.fn();
  const revokePermissionForOrigin = jest.fn();
  const response = {
    result: true,
    id: 1,
    jsonrpc: '2.0' as const,
  };
  const handler = (request: JsonRpcRequest & { origin: string }) =>
    walletRevokeSession.implementation(request, response, next, end, {
      revokePermissionForOrigin,
    });

  return {
    next,
    response,
    end,
    revokePermissionForOrigin,
    handler,
  };
};

describe('wallet_revokeSession', () => {
  it('revokes the the CAIP-25 endowment permission', async () => {
    const { handler, revokePermissionForOrigin } = createMockedHandler();

    await handler(baseRequest);
    expect(revokePermissionForOrigin).toHaveBeenCalledWith(
      Caip25EndowmentPermissionName,
    );
  });

  it('returns true if the CAIP-25 endowment permission does not exist', async () => {
    const { handler, response, revokePermissionForOrigin } =
      createMockedHandler();
    revokePermissionForOrigin.mockImplementation(() => {
      throw new PermissionDoesNotExistError(
        'foo.com',
        Caip25EndowmentPermissionName,
      );
    });

    await handler(baseRequest);
    expect(response.result).toBe(true);
  });

  it('returns true if the subject does not exist', async () => {
    const { handler, response, revokePermissionForOrigin } =
      createMockedHandler();
    revokePermissionForOrigin.mockImplementation(() => {
      throw new UnrecognizedSubjectError('foo.com');
    });

    await handler(baseRequest);
    expect(response.result).toBe(true);
  });

  it('throws an internal RPC error if something unexpected goes wrong with revoking the permission', async () => {
    const { handler, revokePermissionForOrigin, end } = createMockedHandler();
    revokePermissionForOrigin.mockImplementation(() => {
      throw new Error('revoke failed');
    });

    await handler(baseRequest);
    expect(end).toHaveBeenCalledWith(rpcErrors.internal());
  });

  it('returns true if the permission was revoked', async () => {
    const { handler, response } = createMockedHandler();

    await handler(baseRequest);
    expect(response.result).toBe(true);
  });
});

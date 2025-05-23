import { BN } from 'bn.js';

import * as util from './utils';
import type {
  FeeMarketEIP1559Values,
  GasPriceValue,
  TransactionParams,
} from '../types';

const MAX_FEE_PER_GAS = 'maxFeePerGas';
const MAX_PRIORITY_FEE_PER_GAS = 'maxPriorityFeePerGas';
const GAS_PRICE = 'gasPrice';
const FAIL = 'lol';
const PASS = '0x1';

const TRANSACTION_PARAMS_MOCK: TransactionParams = {
  data: 'data',
  from: 'FROM',
  gas: 'gas',
  gasPrice: 'gasPrice',
  nonce: 'nonce',
  to: 'TO',
  value: 'value',
  maxFeePerGas: 'maxFeePerGas',
  maxPriorityFeePerGas: 'maxPriorityFeePerGas',
  estimatedBaseFee: 'estimatedBaseFee',
};

describe('utils', () => {
  describe('normalizeTransactionParams', () => {
    it('normalizes properties', () => {
      const normalized = util.normalizeTransactionParams(
        TRANSACTION_PARAMS_MOCK,
      );

      expect(normalized).toStrictEqual({
        data: '0xdata',
        from: '0xfrom',
        gas: '0xgas',
        gasPrice: '0xgasPrice',
        nonce: '0xnonce',
        to: '0xto',
        value: '0xvalue',
        maxFeePerGas: '0xmaxFeePerGas',
        maxPriorityFeePerGas: '0xmaxPriorityFeePerGas',
        estimatedBaseFee: '0xestimatedBaseFee',
      });
    });

    it('retains legacy type if specified', () => {
      expect(
        util.normalizeTransactionParams({
          ...TRANSACTION_PARAMS_MOCK,
          type: '0x0',
        }),
      ).toStrictEqual(
        expect.objectContaining({
          type: '0x0',
        }),
      );
    });

    it('sets value if not specified', () => {
      expect(
        util.normalizeTransactionParams({
          ...TRANSACTION_PARAMS_MOCK,
          value: undefined,
        }),
      ).toStrictEqual(expect.objectContaining({ value: '0x0' }));
    });

    it('ensures data is even length prefixed hex string', () => {
      expect(
        util.normalizeTransactionParams({
          ...TRANSACTION_PARAMS_MOCK,
          data: '123',
        }),
      ).toStrictEqual(expect.objectContaining({ data: '0x0123' }));
    });

    it('ensures gas is set to gasLimit if gas is not specified', () => {
      expect(
        util.normalizeTransactionParams({
          ...TRANSACTION_PARAMS_MOCK,
          gasLimit: '123',
          gas: undefined,
        }),
      ).toStrictEqual(
        expect.objectContaining({
          gasLimit: '0x123',
          gas: '0x123',
        }),
      );
    });
  });

  describe('isEIP1559Transaction', () => {
    it('should detect EIP1559 transaction', () => {
      const tx: TransactionParams = { from: '' };
      const eip1559tx: TransactionParams = {
        ...tx,
        maxFeePerGas: '2',
        maxPriorityFeePerGas: '3',
      };
      expect(util.isEIP1559Transaction(eip1559tx)).toBe(true);
      expect(util.isEIP1559Transaction(tx)).toBe(false);
    });
  });

  describe('validateGasValues', () => {
    it('should throw when provided invalid gas values', () => {
      const gasValues: GasPriceValue = {
        [GAS_PRICE]: FAIL,
      };
      expect(() => util.validateGasValues(gasValues)).toThrow(TypeError);
      expect(() => util.validateGasValues(gasValues)).toThrow(
        `expected hex string for ${GAS_PRICE} but received: ${FAIL}`,
      );
    });

    it('should throw when any provided gas values are invalid', () => {
      const gasValues: FeeMarketEIP1559Values = {
        [MAX_PRIORITY_FEE_PER_GAS]: PASS,
        [MAX_FEE_PER_GAS]: FAIL,
      };
      expect(() => util.validateGasValues(gasValues)).toThrow(TypeError);
      expect(() => util.validateGasValues(gasValues)).toThrow(
        `expected hex string for ${MAX_FEE_PER_GAS} but received: ${FAIL}`,
      );
    });

    it('should return true when provided valid gas values', () => {
      const gasValues: FeeMarketEIP1559Values = {
        [MAX_FEE_PER_GAS]: PASS,
        [MAX_PRIORITY_FEE_PER_GAS]: PASS,
      };
      expect(() => util.validateGasValues(gasValues)).not.toThrow(TypeError);
    });
  });

  describe('normalizeTxError', () => {
    const errorBase = {
      name: 'TxError',
      message: 'An error occurred',
      stack: 'Error stack trace',
    };
    it('returns the error object with no code and rpc properties', () => {
      const normalizedError = util.normalizeTxError(errorBase);

      expect(normalizedError).toStrictEqual({
        ...errorBase,
        code: undefined,
        rpc: undefined,
      });
    });

    it('returns the error object with code and rpc properties', () => {
      const error = {
        ...errorBase,
        code: 'ERROR_CODE',
        value: { code: 'rpc data' },
      };

      const normalizedError = util.normalizeTxError(error);

      expect(normalizedError).toStrictEqual({
        ...errorBase,
        code: 'ERROR_CODE',
        rpc: { code: 'rpc data' },
      });
    });
  });

  describe('normalizeGasFeeValues', () => {
    it('returns normalized object if legacy gas fees', () => {
      expect(
        // TODO: Replace `any` with type
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        util.normalizeGasFeeValues({ gasPrice: '1A', test: 'value' } as any),
      ).toStrictEqual({ gasPrice: '0x1A' });
    });

    it('returns normalized object if 1559 gas fees', () => {
      expect(
        util.normalizeGasFeeValues({
          maxFeePerGas: '1A',
          maxPriorityFeePerGas: '2B3C',
          test: 'value',
          // TODO: Replace `any` with type
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
        } as any),
      ).toStrictEqual({ maxFeePerGas: '0x1A', maxPriorityFeePerGas: '0x2B3C' });
    });

    it('returns empty 1559 object if missing gas fees', () => {
      expect(
        util.normalizeGasFeeValues({
          test: 'value',
          // TODO: Replace `any` with type
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
        } as any),
      ).toStrictEqual({
        maxFeePerGas: undefined,
        maxPriorityFeePerGas: undefined,
      });
    });
  });

  describe('padHexToEvenLength', () => {
    it('returns same value if already even length and has prefix', () => {
      expect(util.padHexToEvenLength('0x1234')).toBe('0x1234');
    });

    it('returns same value if already even length and no prefix', () => {
      expect(util.padHexToEvenLength('1234')).toBe('1234');
    });

    it('returns padded value if not even length and has prefix', () => {
      expect(util.padHexToEvenLength('0x123')).toBe('0x0123');
    });

    it('returns padded value if not even length and no prefix', () => {
      expect(util.padHexToEvenLength('123')).toBe('0123');
    });

    it('returns same value if prefix only', () => {
      expect(util.padHexToEvenLength('0x')).toBe('0x');
    });

    it('returns padded value if zero', () => {
      expect(util.padHexToEvenLength('0x0')).toBe('0x00');
    });
  });

  describe('getPercentageChange', () => {
    it('supports original and new value as zero', () => {
      expect(util.getPercentageChange(new BN(0), new BN(0))).toBe(0);
    });

    it('supports original value as zero and new value not', () => {
      expect(util.getPercentageChange(new BN(0), new BN(1))).toBe(100);
    });

    it('supports new value greater than original value', () => {
      expect(util.getPercentageChange(new BN(10), new BN(11))).toBe(10);
    });

    it('supports new value less than original value', () => {
      expect(util.getPercentageChange(new BN(11), new BN(10))).toBe(9);
    });

    it('supports large numbers', () => {
      expect(
        util.getPercentageChange(
          new BN(
            '100000000000000000000000000000000000000000000000000000000000000000000000000000000',
          ),
          new BN(
            '200000000000000000000000000000000000000000000000000000000000000000000000000000000',
          ),
        ),
      ).toBe(100);
    });

    it('supports identical original and new value', () => {
      expect(util.getPercentageChange(new BN(1), new BN(1))).toBe(0);
    });

    it('supports negative original value', () => {
      expect(util.getPercentageChange(new BN(-1), new BN(2))).toBe(300);
    });

    it('supports negative new value', () => {
      expect(util.getPercentageChange(new BN(2), new BN(-1))).toBe(150);
    });
  });
});

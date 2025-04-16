import {
  type RateLimitErrorData,
  TOPRFError,
  TORPFErrorCode,
} from '@metamask/toprf-secure-backup';

import { SeedlessOnboardingControllerError } from './constants';

/**
 * Get the error message from the TOPRF error code.
 *
 * @param errorCode - The TOPRF error code.
 * @param defaultMessage - The default error message if the error code is not found.
 * @returns The error message.
 */
function getErrorMessageFromTOPRFErrorCode(
  errorCode: TORPFErrorCode,
  defaultMessage: string,
): string {
  switch (errorCode) {
    case TORPFErrorCode.RateLimitExceeded:
      return 'Too many login attempts';
    case TORPFErrorCode.CouldNotDeriveEncryptionKey:
      return 'Incorrect password';
    default:
      return defaultMessage;
  }
}

/**
 * The RecoveryError class is used to handle errors that occur during the recover encryption key process from the passwrord.
 * It extends the Error class and includes a data property that can be used to store additional information.
 */
export class RecoveryError extends Error {
  data: RateLimitErrorData | undefined;

  constructor(message: string, data?: RateLimitErrorData) {
    super(message);
    this.data = data;
    this.name = 'SeedlessOnboardingController - RecoveryError';
  }

  /**
   * Get an instance of the RecoveryError class.
   *
   * @param error - The error to get the instance of.
   * @returns The instance of the RecoveryError class.
   */
  static getInstance(error: unknown): RecoveryError {
    if (error instanceof TOPRFError) {
      const rateLimitErrorData = RecoveryError.getRateLimitErrorData(error);
      const errorMessage = getErrorMessageFromTOPRFErrorCode(
        error.code,
        SeedlessOnboardingControllerError.LoginFailedError,
      );
      return new RecoveryError(errorMessage, rateLimitErrorData);
    }
    return new RecoveryError(
      SeedlessOnboardingControllerError.LoginFailedError,
    );
  }

  /**
   * Check if the provided error is a rate limit error triggered by too many login attempts.
   *
   * Return a new TooManyLoginAttemptsError if the error is a rate limit error, otherwise undefined.
   *
   * @param error - The error to check.
   * @returns The rate limit error if the error is a rate limit error, otherwise undefined.
   */
  static getRateLimitErrorData(
    error: TOPRFError,
  ): RateLimitErrorData | undefined {
    if (
      error.meta && // error metadata must be present
      error.code === TORPFErrorCode.RateLimitExceeded &&
      typeof error.meta.rateLimitDetails === 'object' &&
      error.meta.rateLimitDetails !== null &&
      'remainingTime' in error.meta.rateLimitDetails &&
      typeof error.meta.rateLimitDetails.remainingTime === 'number' &&
      'message' in error.meta.rateLimitDetails &&
      typeof error.meta.rateLimitDetails.message === 'string' &&
      'isPermanent' in error.meta.rateLimitDetails &&
      typeof error.meta.rateLimitDetails.isPermanent === 'boolean'
    ) {
      return {
        remainingTime: error.meta.rateLimitDetails.remainingTime,
        message: error.meta.rateLimitDetails.message,
        isPermanent: error.meta.rateLimitDetails.isPermanent,
      };
    }
    return undefined;
  }
}

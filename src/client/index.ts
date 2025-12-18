/**
 * Client-side authentication hooks and utilities for zkAuth
 * These are React hooks intended for use in frontend applications
 */

export {
  AUTH_STORAGE_KEY,
  getStoredAuthUser,
  storeAuthUser,
  clearStoredAuthUser,
  updateStoredAuthFlags,
  maskEmail,
  derivePrivateKey,
  deriveLookupKey,
  get2FALocalStorageKey,
  parse2FAData,
  isValid2FASession,
  storeEmailOTP2FAMarker,
  clear2FAData,
} from './authUtils';
export type { GoogleUser, TwoFALocalData } from './authUtils';

export { useZkAuthSession } from './useZkAuthSession';
export type { UseZkAuthSessionReturn } from './useZkAuthSession';

export { useSessionValidation } from './useSessionValidation';
export type { UseSessionValidationProps, UseSessionValidationReturn } from './useSessionValidation';

export { useTwoFactorFlow } from './useTwoFactorFlow';
export type { UseTwoFactorFlowProps, UseTwoFactorFlowReturn } from './useTwoFactorFlow';

export { use2FAStatus } from './use2FAStatus';
export type { Use2FAStatusProps, Use2FAStatusReturn } from './use2FAStatus';

export { useVerifyTOTP } from './useVerifyTOTP';
export type { UseVerifyTOTPProps, UseVerifyTOTPReturn } from './useVerifyTOTP';

export { useVerifyEmailOTP } from './useVerifyEmailOTP';
export type { UseVerifyEmailOTPProps, UseVerifyEmailOTPReturn } from './useVerifyEmailOTP';

export { useSetup2FA } from './useSetup2FA';
export type { UseSetup2FAProps, UseSetup2FAReturn, Setup2FAResult } from './useSetup2FA';

export { useZkAuthFlow } from './useZkAuthFlow';
export type { UseZkAuthFlowProps, UseZkAuthFlowReturn } from './useZkAuthFlow';

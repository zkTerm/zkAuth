/**
 * useVerifyTOTP - Hook for client-side TOTP verification
 * Fetches encrypted secret from on-chain, decrypts with masterKeyHash, verifies code
 */
import { useState, useCallback } from 'react';
import {
  verifyTOTP,
  decryptWithMasterKey,
  get2FAStateFromChain,
  derive2FALookupKeyClient,
  type StorageConfig,
  type EncryptedTwoFAData,
} from '../zk2fa';

export interface UseVerifyTOTPProps {
  email: string;
  googleUserId: string;
  masterKeyHash: string;
  walletAddress?: string;
  encryptedSecret?: EncryptedTwoFAData;
}

export interface UseVerifyTOTPReturn {
  verify: (code: string) => Promise<boolean>;
  loading: boolean;
  error: string | null;
  clearError: () => void;
}

function getHeliusApiKey(): string {
  if (typeof import.meta !== 'undefined' && import.meta.env?.VITE_HELIUS_API_KEY) {
    return import.meta.env.VITE_HELIUS_API_KEY;
  }
  return '';
}

export function useVerifyTOTP({
  email,
  googleUserId,
  masterKeyHash,
  walletAddress,
  encryptedSecret,
}: UseVerifyTOTPProps): UseVerifyTOTPReturn {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const clearError = useCallback(() => {
    setError(null);
  }, []);

  const verify = useCallback(async (code: string): Promise<boolean> => {
    if (!masterKeyHash) {
      setError('Master key hash is required for TOTP verification');
      return false;
    }

    setLoading(true);
    setError(null);

    try {
      let totpSecret: string;

      if (encryptedSecret) {
        totpSecret = await decryptWithMasterKey(encryptedSecret, masterKeyHash);
      } else {
        const heliusApiKey = getHeliusApiKey();
        if (!heliusApiKey) {
          setError('Helius API key not configured');
          setLoading(false);
          return false;
        }

        const effectiveWallet = walletAddress || derive2FALookupKeyClient(email, googleUserId);
        
        const config: StorageConfig = {
          helius: {
            apiKey: heliusApiKey,
            cluster: 'mainnet-beta',
          },
          timeout: 15000,
        };

        const state = await get2FAStateFromChain(
          email,
          googleUserId,
          effectiveWallet,
          config
        );

        if (!state || !state.totpSecret) {
          setError('TOTP not configured for this account');
          setLoading(false);
          return false;
        }

        totpSecret = state.totpSecret;
      }

      const isValid = verifyTOTP(code, totpSecret);

      if (!isValid) {
        setError('Invalid TOTP code');
      }

      return isValid;
    } catch (err) {
      console.error('[useVerifyTOTP] Verification error:', err);
      setError(err instanceof Error ? err.message : 'TOTP verification failed');
      return false;
    } finally {
      setLoading(false);
    }
  }, [email, googleUserId, masterKeyHash, walletAddress, encryptedSecret]);

  return {
    verify,
    loading,
    error,
    clearError,
  };
}

/**
 * use2FAStatus - Hook to get 2FA status from on-chain data
 * Fetches TwoFAState from Solana memos using Helius API
 */
import { useState, useEffect, useCallback } from 'react';
import {
  get2FAStateFromChain,
  derive2FALookupKeyClient,
  type StorageConfig,
  type TwoFAState,
} from '../zk2fa';

export interface Use2FAStatusProps {
  email: string;
  googleUserId: string;
  masterKeyHash: string;
  walletAddress?: string;
}

export interface Use2FAStatusReturn {
  totpEnabled: boolean;
  emailOtpEnabled: boolean;
  twoFAState: TwoFAState | null;
  loading: boolean;
  error: string | null;
  refetch: () => Promise<void>;
}

const SESSION_TOKEN_KEY = 'zkterm_session_token';

function getHeliusApiKey(): string {
  if (typeof import.meta !== 'undefined' && import.meta.env?.VITE_HELIUS_API_KEY) {
    return import.meta.env.VITE_HELIUS_API_KEY;
  }
  return '';
}

export function use2FAStatus({
  email,
  googleUserId,
  masterKeyHash,
  walletAddress,
}: Use2FAStatusProps): Use2FAStatusReturn {
  const [twoFAState, setTwoFAState] = useState<TwoFAState | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchStatus = useCallback(async () => {
    if (!email || !googleUserId) {
      setError('Email and googleUserId are required');
      return;
    }

    const heliusApiKey = getHeliusApiKey();
    if (!heliusApiKey) {
      setError('Helius API key not configured');
      return;
    }

    const effectiveWallet = walletAddress || derive2FALookupKeyClient(email, googleUserId);

    setLoading(true);
    setError(null);

    try {
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

      if (state) {
        setTwoFAState(state);
      } else {
        setTwoFAState({
          totpSecret: '',
          totpEnabled: false,
          totpBackupCodes: [],
          totpEnabledAt: null,
          emailOtpEnabled: false,
        });
      }
    } catch (err) {
      console.error('[use2FAStatus] Error fetching 2FA status:', err);
      setError(err instanceof Error ? err.message : 'Failed to fetch 2FA status');
    } finally {
      setLoading(false);
    }
  }, [email, googleUserId, walletAddress]);

  useEffect(() => {
    if (email && googleUserId) {
      fetchStatus();
    }
  }, [email, googleUserId, fetchStatus]);

  return {
    totpEnabled: twoFAState?.totpEnabled ?? false,
    emailOtpEnabled: twoFAState?.emailOtpEnabled ?? false,
    twoFAState,
    loading,
    error,
    refetch: fetchStatus,
  };
}

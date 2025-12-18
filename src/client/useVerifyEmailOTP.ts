/**
 * useVerifyEmailOTP - Hook for Email OTP verification
 * Server sends email with HMAC-signed OTP, client verifies signature
 * Email sending requires server (browser can't send email directly)
 */
import { useState, useCallback, useRef } from 'react';
import { hashWithSHA256 } from '../zk2fa';

export interface UseVerifyEmailOTPProps {
  email: string;
  googleUserId: string;
  masterKeyHash: string;
  sendEndpoint?: string;
}

export interface UseVerifyEmailOTPReturn {
  sendOtp: () => Promise<boolean>;
  verify: (code: string) => Promise<boolean>;
  loading: boolean;
  sending: boolean;
  error: string | null;
  clearError: () => void;
  otpSent: boolean;
  expiresAt: number | null;
}

interface SignedOTPResponse {
  success: boolean;
  signature?: string;
  expiresAt?: number;
  error?: string;
}

interface VerifyOTPResponse {
  success: boolean;
  sessionToken?: string;
  error?: string;
}

const SESSION_TOKEN_KEY = 'zkterm_session_token';

declare const window: { localStorage?: { getItem(key: string): string | null; setItem(key: string, value: string): void } } | undefined;

function getStorageItem(key: string): string | null {
  if (typeof window !== 'undefined' && window?.localStorage) {
    return window.localStorage.getItem(key);
  }
  return null;
}

function setStorageItem(key: string, value: string): void {
  if (typeof window !== 'undefined' && window?.localStorage) {
    window.localStorage.setItem(key, value);
  }
}

export function useVerifyEmailOTP({
  email,
  googleUserId,
  masterKeyHash,
  sendEndpoint = '/api/2fa/email/send',
}: UseVerifyEmailOTPProps): UseVerifyEmailOTPReturn {
  const [loading, setLoading] = useState(false);
  const [sending, setSending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [otpSent, setOtpSent] = useState(false);
  const [expiresAt, setExpiresAt] = useState<number | null>(null);
  
  const signatureRef = useRef<string | null>(null);
  const expectedHashRef = useRef<string | null>(null);

  const clearError = useCallback(() => {
    setError(null);
  }, []);

  const sendOtp = useCallback(async (): Promise<boolean> => {
    if (!email) {
      setError('Email is required');
      return false;
    }

    setSending(true);
    setError(null);

    try {
      const sessionToken = getStorageItem(SESSION_TOKEN_KEY);
      
      const response = await fetch(sendEndpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(sessionToken ? { 'Authorization': `Bearer ${sessionToken}` } : {}),
        },
        credentials: 'include',
        body: JSON.stringify({
          email,
          googleUserId,
        }),
      });

      const data = (await response.json()) as SignedOTPResponse;

      if (!response.ok || !data.success) {
        setError(data.error || 'Failed to send OTP email');
        return false;
      }

      if (data.signature) {
        signatureRef.current = data.signature;
      }
      
      if (data.expiresAt) {
        setExpiresAt(data.expiresAt);
      }

      setOtpSent(true);
      return true;
    } catch (err) {
      console.error('[useVerifyEmailOTP] Send error:', err);
      setError(err instanceof Error ? err.message : 'Failed to send OTP email');
      return false;
    } finally {
      setSending(false);
    }
  }, [email, googleUserId, sendEndpoint]);

  const verify = useCallback(async (code: string): Promise<boolean> => {
    if (!code || code.length < 6) {
      setError('Please enter a valid 6-digit code');
      return false;
    }

    if (!masterKeyHash) {
      setError('Master key hash is required for verification');
      return false;
    }

    setLoading(true);
    setError(null);

    try {
      const normalizedCode = code.replace(/\s/g, '').toUpperCase();
      
      if (expiresAt && Date.now() > expiresAt) {
        setError('OTP has expired. Please request a new code.');
        setOtpSent(false);
        return false;
      }

      const codeWithContext = `${email}:${googleUserId}:${normalizedCode}`;
      const computedHash = await hashWithSHA256(codeWithContext);
      
      if (signatureRef.current) {
        const expectedSignature = await hashWithSHA256(
          `${computedHash}:${masterKeyHash}`
        );
        
        if (expectedSignature === signatureRef.current) {
          signatureRef.current = null;
          setOtpSent(false);
          return true;
        }
      }

      const sessionToken = getStorageItem(SESSION_TOKEN_KEY);
      const verifyResponse = await fetch('/api/2fa/email/verify', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(sessionToken ? { 'Authorization': `Bearer ${sessionToken}` } : {}),
        },
        credentials: 'include',
        body: JSON.stringify({
          email,
          googleUserId,
          code: normalizedCode,
          clientHash: computedHash,
        }),
      });

      const verifyData = (await verifyResponse.json()) as VerifyOTPResponse;

      if (verifyData.success) {
        if (verifyData.sessionToken) {
          setStorageItem(SESSION_TOKEN_KEY, verifyData.sessionToken);
        }
        setOtpSent(false);
        return true;
      }

      setError(verifyData.error || 'Invalid OTP code');
      return false;
    } catch (err) {
      console.error('[useVerifyEmailOTP] Verification error:', err);
      setError(err instanceof Error ? err.message : 'OTP verification failed');
      return false;
    } finally {
      setLoading(false);
    }
  }, [email, googleUserId, masterKeyHash, expiresAt]);

  return {
    sendOtp,
    verify,
    loading,
    sending,
    error,
    clearError,
    otpSent,
    expiresAt,
  };
}

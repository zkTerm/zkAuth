/**
 * useSetup2FA - Hook for client-side 2FA setup
 * Generates TOTP secret, encrypts with masterKeyHash, stores locally
 */
import { useState, useCallback } from 'react';
import {
  generateTOTPSecret,
  generateTOTPUri,
  verifyTOTP,
  encryptWithMasterKey,
  hashWithSHA256,
  type EncryptedTwoFAData,
} from '../zk2fa';
import QRCode from 'qrcode';

export interface UseSetup2FAProps {
  email: string;
  googleUserId: string;
  masterKeyHash: string;
}

export interface Setup2FAResult {
  secret: string;
  qrCodeDataUrl: string;
  backupCodes: string[];
}

export interface UseSetup2FAReturn {
  initiateSetup: () => Promise<Setup2FAResult>;
  completeSetup: (code: string) => Promise<{ success: boolean; error?: string }>;
  confirmBackupCodes: () => void;
  pendingSetup: { secret: string; backupCodes: string[] } | null;
  loading: boolean;
  error: string | null;
}

function generateBackupCodes(count: number = 8): string[] {
  const codes: string[] = [];
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  
  for (let i = 0; i < count; i++) {
    let code = '';
    for (let j = 0; j < 8; j++) {
      code += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    codes.push(code.slice(0, 4) + '-' + code.slice(4));
  }
  
  return codes;
}

function derive2FAStorageKey(email: string, googleUserId: string): string {
  const combined = `${email}:${googleUserId}`;
  let hash = 0;
  for (let i = 0; i < combined.length; i++) {
    const char = combined.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash;
  }
  return `zkterm:2fa:${Math.abs(hash).toString(36)}`;
}

export function useSetup2FA({
  email,
  googleUserId,
  masterKeyHash,
}: UseSetup2FAProps): UseSetup2FAReturn {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pendingSetup, setPendingSetup] = useState<{
    secret: string;
    backupCodes: string[];
    backupCodesHashed: string[];
  } | null>(null);

  const initiateSetup = useCallback(async (): Promise<Setup2FAResult> => {
    setLoading(true);
    setError(null);

    try {
      const secret = generateTOTPSecret();
      const uri = generateTOTPUri(secret, email);
      const backupCodes = generateBackupCodes(8);
      
      const backupCodesHashed = await Promise.all(
        backupCodes.map(code => hashWithSHA256(code.replace('-', '').toUpperCase()))
      );

      const qrCodeDataUrl = await QRCode.toDataURL(uri, {
        width: 200,
        margin: 2,
        color: { dark: '#000000', light: '#ffffff' }
      });

      setPendingSetup({ secret, backupCodes, backupCodesHashed });

      return {
        secret,
        qrCodeDataUrl,
        backupCodes,
      };
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : 'Failed to initialize 2FA setup';
      setError(errorMsg);
      throw err;
    } finally {
      setLoading(false);
    }
  }, [email]);

  const completeSetup = useCallback(async (
    code: string
  ): Promise<{ success: boolean; error?: string }> => {
    if (!pendingSetup) {
      return { success: false, error: 'No pending setup' };
    }

    if (!masterKeyHash) {
      return { success: false, error: 'Master key hash required for encryption' };
    }

    setLoading(true);
    setError(null);

    try {
      const isValid = verifyTOTP(code, pendingSetup.secret);
      
      if (!isValid) {
        setError('Invalid verification code');
        setLoading(false);
        return { success: false, error: 'Invalid verification code' };
      }

      const encryptedSecret = await encryptWithMasterKey(pendingSetup.secret, masterKeyHash);

      const totpData = {
        encryptedSecret,
        backupCodesHashed: pendingSetup.backupCodesHashed,
        createdAt: Date.now(),
        version: 1,
      };

      const storageKey = derive2FAStorageKey(email, googleUserId);
      const storage = typeof globalThis !== 'undefined' ? (globalThis as any).localStorage : null;
      if (storage) {
        storage.setItem(storageKey, JSON.stringify(totpData));
      }

      setLoading(false);
      return { success: true };
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : 'Setup failed';
      setError(errorMsg);
      setLoading(false);
      return { success: false, error: errorMsg };
    }
  }, [pendingSetup, masterKeyHash, email, googleUserId]);

  const confirmBackupCodes = useCallback(() => {
    setPendingSetup(null);
  }, []);

  return {
    initiateSetup,
    completeSetup,
    confirmBackupCodes,
    pendingSetup: pendingSetup ? {
      secret: pendingSetup.secret,
      backupCodes: pendingSetup.backupCodes,
    } : null,
    loading,
    error,
  };
}

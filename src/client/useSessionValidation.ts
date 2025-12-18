/**
 * useSessionValidation - Hook for validating zkAuth session state
 * Ensures logged-in users have valid decentralized 2FA data
 */
import { useRef, useEffect, useCallback } from 'react';
import { activityLogger } from '@/lib/activityLogger';
import { 
  deriveLookupKey, 
  get2FALocalStorageKey, 
  parse2FAData,
  isValid2FASession 
} from './authUtils';
import type { GoogleUser } from './useZkAuthSession';

export interface UseSessionValidationProps {
  isLoggedIn: boolean;
  googleUser: GoogleUser | null | undefined;
  secretPhrase: string;
  showMandatory2FASetup: boolean;
  isAwaiting2FARef: React.MutableRefObject<boolean>;
  showAlert: (type: "success" | "error", title: string, message: string) => void;
  refetchUser: () => Promise<unknown>;
  setShowMandatory2FASetup: (show: boolean) => void;
}

export interface UseSessionValidationReturn {
  sessionValidationDoneRef: React.MutableRefObject<boolean>;
}

/**
 * Validates session state for logged-in users
 * - Checks for valid decentralized 2FA data in localStorage
 * - Forces 2FA setup if missing
 * - Forces logout if session is invalid (no secret phrase)
 */
export function useSessionValidation({
  isLoggedIn,
  googleUser,
  secretPhrase,
  showMandatory2FASetup,
  isAwaiting2FARef,
  showAlert,
  refetchUser,
  setShowMandatory2FASetup,
}: UseSessionValidationProps): UseSessionValidationReturn {
  const sessionValidationDoneRef = useRef(false);
  
  // Force logout helper
  const forceLogout = useCallback(async (lookupKey: string) => {
    const localStorageKey = get2FALocalStorageKey(lookupKey);
    
    activityLogger.error("zkAuth", "Invalid session: No secret phrase for 2FA encryption - forcing logout");
    
    await fetch("/api/oauth/google/logout", { method: "POST", credentials: "include" });
    await fetch("/api/zkauth/logout", { method: "POST", credentials: "include" });
    
    localStorage.removeItem(localStorageKey);
    
    showAlert("error", "Session Invalid", "Your session was incomplete. Please log in again.");
    refetchUser();
  }, [showAlert, refetchUser]);
  
  // Require 2FA setup helper
  const require2FASetup = useCallback(() => {
    isAwaiting2FARef.current = true;
    setShowMandatory2FASetup(true);
  }, [isAwaiting2FARef, setShowMandatory2FASetup]);
  
  useEffect(() => {
    const validateSession = async () => {
      // Only check once per mount, and only if user appears logged in
      if (sessionValidationDoneRef.current || !isLoggedIn || !googleUser) {
        return;
      }
      sessionValidationDoneRef.current = true;

      try {
        const lookupKey = await deriveLookupKey(googleUser.email, googleUser.googleUserId);
        const localStorageKey = get2FALocalStorageKey(lookupKey);
        
        const stored2FA = localStorage.getItem(localStorageKey);
        const parsedData = parse2FAData(stored2FA);
        
        // If user is logged in but has no 2FA data, session is incomplete
        // However, we should NOT force logout if they're in the middle of 2FA setup
        if (!stored2FA && !showMandatory2FASetup && !isAwaiting2FARef.current) {
          activityLogger.info("zkAuth", "Session validation: No decentralized 2FA data found");
          activityLogger.info("zkAuth", "Requiring 2FA setup for session completion...");
          
          // Instead of forcing logout, prompt 2FA setup if secret phrase is available
          if (secretPhrase) {
            require2FASetup();
          } else {
            // No secret phrase - this is an invalid session state
            await forceLogout(lookupKey);
          }
        } else if (stored2FA) {
          // Validate the stored 2FA data structure
          if (parsedData?.disabled) {
            // 2FA was explicitly disabled - this might need re-setup
            activityLogger.info("zkAuth", "2FA was disabled - may need re-setup");
          } else if (parsedData?.method === 'email' && parsedData?.verified) {
            // Email OTP 2FA - valid session (verified via server-side OTP)
            activityLogger.info("zkAuth", "Session validated: Email OTP 2FA active");
          } else if (!parsedData?.encryptedSecret && parsedData?.method !== 'email') {
            // Corrupted data (not Email OTP and no encrypted secret)
            activityLogger.error("zkAuth", "Corrupted 2FA data - clearing and requiring re-setup");
            localStorage.removeItem(localStorageKey);
            if (secretPhrase) {
              require2FASetup();
            }
          } else if (parsedData === null) {
            // Invalid JSON - clear and require re-setup
            activityLogger.error("zkAuth", "Invalid 2FA data format - clearing");
            localStorage.removeItem(localStorageKey);
          }
        }
      } catch (err) {
        console.error("[zkAuth] Session validation error:", err);
      }
    };

    validateSession();
  }, [isLoggedIn, googleUser, secretPhrase, showMandatory2FASetup, isAwaiting2FARef, showAlert, refetchUser, forceLogout, require2FASetup]);
  
  return {
    sessionValidationDoneRef,
  };
}

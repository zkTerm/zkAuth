/**
 * useTwoFactorFlow - Hook for managing 2FA verification and setup flows
 * Extracts Email OTP and TOTP orchestration from home.tsx
 */
import { useState, useCallback } from 'react';
import { activityLogger } from '@/lib/activityLogger';
import { storeEmailOTP2FAMarker, updateStoredAuthFlags, clearStoredAuthUser } from './authUtils';
import type { GoogleUser } from './authUtils';

export interface UseTwoFactorFlowProps {
  googleUser: GoogleUser | null | undefined;
  oauthFlowProcessedRef: React.MutableRefObject<boolean>;
  reloadCheckDoneRef: React.MutableRefObject<boolean>;
  isAwaiting2FARef: React.MutableRefObject<boolean>;
  userDismissedAuthRef: React.MutableRefObject<boolean>;
  refetchUser: () => Promise<unknown>;
  setIsProcessing: (processing: boolean) => void;
  setProcessingMessage: (message: string) => void;
}

export interface UseTwoFactorFlowReturn {
  // Modal visibility states
  showTotpModal: boolean;
  setShowTotpModal: (show: boolean) => void;
  showEmailOtpModal: boolean;
  setShowEmailOtpModal: (show: boolean) => void;
  showMandatory2FASetup: boolean;
  setShowMandatory2FASetup: (show: boolean) => void;
  
  // TOTP state
  totpCode: string;
  setTotpCode: (code: string) => void;
  totpError: string;
  setTotpError: (error: string) => void;
  
  // Handlers
  handleTotpSubmit: (code: string) => Promise<void>;
  handleMandatory2FAComplete: () => Promise<void>;
  handleEmailOtpSuccess: () => Promise<void>;
  handleEmailOtpCancel: () => Promise<void>;
  
  // Helper to show correct 2FA modal based on method
  show2FAModal: (method: 'totp' | 'email') => void;
}

export function useTwoFactorFlow({
  googleUser,
  oauthFlowProcessedRef,
  reloadCheckDoneRef,
  isAwaiting2FARef,
  userDismissedAuthRef,
  refetchUser,
  setIsProcessing,
  setProcessingMessage,
}: UseTwoFactorFlowProps): UseTwoFactorFlowReturn {
  // Modal states
  const [showTotpModal, setShowTotpModal] = useState(false);
  const [showEmailOtpModal, setShowEmailOtpModal] = useState(false);
  const [showMandatory2FASetup, setShowMandatory2FASetup] = useState(false);
  
  // TOTP state
  const [totpCode, setTotpCode] = useState("");
  const [totpError, setTotpError] = useState("");
  
  // Helper to show correct 2FA modal based on method
  const show2FAModal = useCallback((method: 'totp' | 'email') => {
    isAwaiting2FARef.current = true;
    if (method === 'email') {
      setShowEmailOtpModal(true);
    } else {
      setShowTotpModal(true);
    }
  }, [isAwaiting2FARef]);
  
  // Handle TOTP verification
  const handleTotpSubmit = useCallback(async (code: string) => {
    setTotpError("");
    setIsProcessing(true);
    setProcessingMessage("Verifying 2FA code...");
    
    try {
      const response = await fetch("/api/2fa/validate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code }),
        credentials: "include",
      });
      
      const data = await response.json();
      
      if (data.success) {
        // Store decentralized session token in localStorage if provided
        if (data.sessionToken) {
          localStorage.setItem('zkterm_session_token', data.sessionToken);
          console.log('[zkAuth] Session token stored in localStorage');
        }
        
        activityLogger.success("zkAuth", "2FA verified - login complete");
        setShowTotpModal(false);
        setTotpCode("");
        isAwaiting2FARef.current = false;
        
        // CRITICAL: Prevent reload effect from re-triggering login after successful 2FA
        reloadCheckDoneRef.current = true;
        oauthFlowProcessedRef.current = true;
        
        // CRITICAL: Update localStorage flags BEFORE refetch to mark user as fully authenticated
        updateStoredAuthFlags({ isRegistered: true, masterKeyDistributed: true });
        
        setIsProcessing(false);
        await refetchUser();
      } else {
        setTotpError(data.error || "Invalid code");
        setIsProcessing(false);
      }
    } catch (error) {
      console.error("[zkAuth] 2FA verification failed:", error);
      setTotpError("Verification failed. Please try again.");
      setIsProcessing(false);
    }
  }, [oauthFlowProcessedRef, reloadCheckDoneRef, isAwaiting2FARef, refetchUser, setIsProcessing, setProcessingMessage]);
  
  // Handle mandatory 2FA setup completion
  const handleMandatory2FAComplete = useCallback(async () => {
    activityLogger.success("zkAuth", "2FA setup complete");
    setShowMandatory2FASetup(false);
    isAwaiting2FARef.current = false;
    
    // CRITICAL: Prevent reload effect from re-triggering login after successful 2FA setup
    reloadCheckDoneRef.current = true;
    oauthFlowProcessedRef.current = true;
    
    // CRITICAL: Update localStorage flags BEFORE refetch to mark user as fully authenticated
    updateStoredAuthFlags({ isRegistered: true, masterKeyDistributed: true });
    
    await refetchUser();
  }, [oauthFlowProcessedRef, reloadCheckDoneRef, isAwaiting2FARef, refetchUser]);
  
  // Handle Email OTP verification success
  const handleEmailOtpSuccess = useCallback(async () => {
    activityLogger.success("zkAuth", "Email OTP verified - login complete");
    setShowEmailOtpModal(false);
    isAwaiting2FARef.current = false;
    
    // CRITICAL: Prevent reload effect from re-triggering login after successful 2FA
    reloadCheckDoneRef.current = true;
    oauthFlowProcessedRef.current = true;
    
    // CRITICAL: Update localStorage flags BEFORE refetch to mark user as fully authenticated
    updateStoredAuthFlags({ isRegistered: true, masterKeyDistributed: true });
    
    // Store Email OTP marker in localStorage for session validation
    if (googleUser) {
      try {
        await storeEmailOTP2FAMarker(googleUser.email, googleUser.googleUserId);
        activityLogger.info("zkAuth", "Email OTP 2FA marker saved to localStorage");
      } catch (err) {
        console.error("[zkAuth] Failed to store Email OTP marker:", err);
      }
    }
    
    await refetchUser();
  }, [googleUser, oauthFlowProcessedRef, reloadCheckDoneRef, isAwaiting2FARef, refetchUser]);
  
  // Handle Email OTP verification cancel - auto logout since 2FA is required
  const handleEmailOtpCancel = useCallback(async () => {
    setShowEmailOtpModal(false);
    isAwaiting2FARef.current = false;
    
    // CRITICAL: Mark that user dismissed auth to prevent modal re-appearing
    userDismissedAuthRef.current = true;
    
    // CRITICAL: Prevent reload effect from re-triggering login after logout
    reloadCheckDoneRef.current = true;
    oauthFlowProcessedRef.current = true;
    
    activityLogger.info("zkAuth", "Email OTP verification cancelled - logging out");
    
    // Auto logout since user cancelled required 2FA verification
    try {
      await fetch("/api/2fa/cancel", { method: "POST", credentials: "include" });
      await fetch("/api/oauth/google/logout", { method: "POST", credentials: "include" });
      await fetch("/api/zkauth/logout", { method: "POST", credentials: "include" });
    } catch (err) {
      console.error("[zkAuth] Logout error:", err);
    }
    
    // CRITICAL: Clear cached auth user to prevent auto-login on page reload
    clearStoredAuthUser();
    
    // Full page refresh to clear all cached state
    window.location.href = "/";
  }, [oauthFlowProcessedRef, reloadCheckDoneRef, isAwaiting2FARef, userDismissedAuthRef]);
  
  return {
    showTotpModal,
    setShowTotpModal,
    showEmailOtpModal,
    setShowEmailOtpModal,
    showMandatory2FASetup,
    setShowMandatory2FASetup,
    totpCode,
    setTotpCode,
    totpError,
    setTotpError,
    handleTotpSubmit,
    handleMandatory2FAComplete,
    handleEmailOtpSuccess,
    handleEmailOtpCancel,
    show2FAModal,
  };
}

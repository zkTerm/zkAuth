/**
 * useZkAuthFlow - Hook for managing the complete zkAuth flow
 * Encapsulates OAuth callback, on-chain checks, login/registration logic
 * Now also manages 2FA flow internally to avoid circular dependencies
 */
import { useEffect, useRef, useCallback } from 'react';
import { useQuery } from '@tanstack/react-query';
import { activityLogger } from '@/lib/activityLogger';
import { getStoredAuthUser, storeAuthUser, derivePrivateKey, type GoogleUser } from './authUtils';
import { useTwoFactorFlow, type UseTwoFactorFlowReturn } from './useTwoFactorFlow';

export interface UseZkAuthFlowProps {
  search: string;
  setActiveTab: (tab: 'home' | 'terminal' | 'explorer') => void;
  setIsProcessing: (processing: boolean) => void;
  setProcessingMessage: (message: string) => void;
  setTwoFactorStatus: (status: { totp: boolean; email: boolean }) => void;
  showAlert: (type: "success" | "error", title: string, message: string) => void;
  showSecretPhraseModal: boolean;
  setShowSecretPhraseModal: (show: boolean) => void;
}

export interface UseZkAuthFlowReturn {
  googleUser: GoogleUser | null | undefined;
  isLoggedIn: boolean;
  refetchUser: () => Promise<unknown>;
  handleGoogleLogin: () => void;
  handleSecretPhraseSubmit: (submittedPhrase: string) => Promise<void>;
  oauthFlowProcessedRef: React.MutableRefObject<boolean>;
  reloadCheckDoneRef: React.MutableRefObject<boolean>;
  isAwaiting2FARef: React.MutableRefObject<boolean>;
  userDismissedAuthRef: React.MutableRefObject<boolean>;
  twoFactorFlow: UseTwoFactorFlowReturn;
}

export function useZkAuthFlow({
  search,
  setActiveTab,
  setIsProcessing,
  setProcessingMessage,
  setTwoFactorStatus,
  showAlert,
  showSecretPhraseModal,
  setShowSecretPhraseModal,
}: UseZkAuthFlowProps): UseZkAuthFlowReturn {
  const oauthFlowProcessedRef = useRef(false);
  const isAwaiting2FARef = useRef(false);
  const reloadCheckDoneRef = useRef(false);
  const prevIsLoggedInRef = useRef<boolean | undefined>(undefined);
  const userDismissedAuthRef = useRef(false);
  
  const { data: googleUser, refetch: refetchUser } = useQuery<GoogleUser | null>({
    queryKey: ["zkauth-user"],
    queryFn: async () => {
      const params = new URLSearchParams(window.location.search);
      const isOAuthCallback = params.get("oauth") === "success";
      
      if (isOAuthCallback) {
        const response = await fetch("/api/oauth/google/user", { credentials: "include" });
        if (!response.ok) return null;
        const data = await response.json();
        if (!data.authenticated) return null;
        const user: GoogleUser = {
          googleUserId: data.googleUserId,
          email: data.email,
          name: data.name,
          picture: data.picture,
          isRegistered: data.isRegistered,
          masterKeyDistributed: data.masterKeyDistributed,
        };
        storeAuthUser(user);
        return user;
      }
      
      const cachedUser = getStoredAuthUser();
      if (cachedUser) {
        return cachedUser;
      }
      
      try {
        const response = await fetch("/api/oauth/google/user", { credentials: "include" });
        if (!response.ok) return null;
        const data = await response.json();
        if (!data.authenticated) return null;
        const user: GoogleUser = {
          googleUserId: data.googleUserId,
          email: data.email,
          name: data.name,
          picture: data.picture,
          isRegistered: data.isRegistered,
          masterKeyDistributed: data.masterKeyDistributed,
        };
        storeAuthUser(user);
        return user;
      } catch {
        return null;
      }
    },
    staleTime: Infinity,
  });
  
  const isLoggedIn = !!(googleUser?.isRegistered && googleUser?.masterKeyDistributed);
  
  const twoFactorFlow = useTwoFactorFlow({
    googleUser,
    oauthFlowProcessedRef,
    reloadCheckDoneRef,
    isAwaiting2FARef,
    userDismissedAuthRef,
    refetchUser,
    setIsProcessing,
    setProcessingMessage,
  });
  
  useEffect(() => {
    const wasLoggedIn = prevIsLoggedInRef.current;
    const nowLoggedIn = isLoggedIn;
    prevIsLoggedInRef.current = nowLoggedIn;
    
    if (wasLoggedIn && !nowLoggedIn && !googleUser) {
      oauthFlowProcessedRef.current = false;
      reloadCheckDoneRef.current = false;
      isAwaiting2FARef.current = false;
    }
  }, [isLoggedIn, googleUser]);
  
  const processLoginResponse = useCallback(async (loginData: any, user: GoogleUser) => {
    if (loginData.success && loginData.needs2FASetup) {
      setProcessingMessage("2FA setup required...");
      activityLogger.info("zkAuth", "No 2FA configured - requiring setup");
      setIsProcessing(false);
      isAwaiting2FARef.current = true;
      twoFactorFlow.setShowMandatory2FASetup(true);
      return true;
    } else if (loginData.success && loginData.needs2FA) {
      setProcessingMessage("2FA verification required...");
      const method = loginData.twoFAMethod || 'totp';
      activityLogger.info("zkAuth", `2FA enabled (${method}) - awaiting code`);
      setIsProcessing(false);
      isAwaiting2FARef.current = true;
      if (method === 'email') {
        twoFactorFlow.setShowEmailOtpModal(true);
      } else {
        twoFactorFlow.setShowTotpModal(true);
      }
      return true;
    } else if (loginData.success) {
      setProcessingMessage("Master key reconstructed!");
      activityLogger.success("zkAuth", "Master key reconstructed - welcome back!");
      if (user?.googleUserId && user?.email) {
        storeAuthUser({
          googleUserId: user.googleUserId,
          email: user.email,
          name: user.name,
          picture: user.picture,
          isRegistered: true,
          masterKeyDistributed: true,
        });
      }
      setTwoFactorStatus({
        totp: loginData.twoFAMethods?.includes('totp') ?? false,
        email: loginData.twoFAMethods?.includes('email') ?? false
      });
      setIsProcessing(false);
      await refetchUser();
      return true;
    } else if (loginData.needsRegistration) {
      activityLogger.info("zkAuth", "Shares not found, showing registration...");
      setIsProcessing(false);
      setShowSecretPhraseModal(true);
      return true;
    }
    return false;
  }, [twoFactorFlow, setIsProcessing, setProcessingMessage, setTwoFactorStatus, refetchUser, setShowSecretPhraseModal]);
  
  useEffect(() => {
    const params = new URLSearchParams(search);
    const oauthSuccess = params.get("oauth") === "success";
    const error = params.get("error");
    
    if (error) {
      const errorMessages: Record<string, string> = {
        oauth_denied: "Google login was cancelled",
        no_code: "No authorization code received",
        invalid_state: "Invalid session state",
        no_token: "No token received from Google",
        invalid_token: "Invalid token from Google",
        callback_failed: "Authentication callback failed",
      };
      showAlert("error", "Authentication Error", errorMessages[error] || "Login failed");
      window.history.replaceState({}, '', '/');
      return;
    }
    
    if (oauthSuccess && googleUser && !oauthFlowProcessedRef.current) {
      oauthFlowProcessedRef.current = true;
      window.history.replaceState({}, '', '/');
      setActiveTab('explorer');
      activityLogger.info("zkAuth", "Google OAuth successful - checking on-chain registration...");
      
      (async () => {
        try {
          const onChainCheck = await fetch("/api/zkauth/check-user-onchain", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email: googleUser.email }),
            credentials: "include",
          });
          
          const onChainData = await onChainCheck.json();
          const isRegisteredOnChain = onChainData.exists === true;
          
          activityLogger.info("zkAuth", `On-chain lookup: ${isRegisteredOnChain ? "User exists" : "New user"}`);
          
          if (!isRegisteredOnChain) {
            setShowSecretPhraseModal(true);
          } else {
            activityLogger.info("zkAuth", "Returning user - auto-login with Google credentials...");
            setIsProcessing(true);
            setProcessingMessage("Reconstructing master key from blockchain...");
            
            try {
              const loginResponse = await fetch("/api/zkauth/login", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ 
                  email: googleUser.email, 
                  googleUserId: googleUser.googleUserId 
                }),
                credentials: "include",
              });
              
              const loginData = await loginResponse.json();
              const handled = await processLoginResponse(loginData, googleUser);
              
              if (!handled) {
                throw new Error(loginData.error || "Login failed");
              }
            } catch (loginErr) {
              console.error("[zkAuth] Auto-login failed:", loginErr);
              activityLogger.error("zkAuth", "Auto-login failed");
              setIsProcessing(false);
              showAlert("error", "Login Failed", "Could not reconstruct master key");
            }
          }
          
          await refetchUser();
        } catch (err) {
          console.error("[zkAuth] On-chain check failed:", err);
          activityLogger.error("zkAuth", "On-chain check failed, falling back to DB");
          
          if (!googleUser.isRegistered) {
            setShowSecretPhraseModal(true);
          } else {
            setIsProcessing(true);
            setProcessingMessage("Reconstructing master key...");
            try {
              const loginResponse = await fetch("/api/zkauth/login", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ 
                  email: googleUser.email, 
                  googleUserId: googleUser.googleUserId 
                }),
                credentials: "include",
              });
              const loginData = await loginResponse.json();
              const handled = await processLoginResponse(loginData, googleUser);
              if (!handled && !isAwaiting2FARef.current) {
                setShowSecretPhraseModal(true);
              }
            } catch {
              if (!isAwaiting2FARef.current) {
                setShowSecretPhraseModal(true);
              }
            }
            setIsProcessing(false);
          }
        }
      })();
    }
  }, [search, googleUser, setActiveTab, setIsProcessing, setProcessingMessage, showAlert, setShowSecretPhraseModal, processLoginResponse, refetchUser]);

  useEffect(() => {
    const params = new URLSearchParams(search);
    const oauthSuccess = params.get("oauth") === "success";
    
    if (googleUser && !oauthSuccess && !isLoggedIn && !reloadCheckDoneRef.current && !userDismissedAuthRef.current && !showSecretPhraseModal && !twoFactorFlow.showMandatory2FASetup && !twoFactorFlow.showEmailOtpModal && !twoFactorFlow.showTotpModal) {
      reloadCheckDoneRef.current = true;
      
      (async () => {
        try {
          activityLogger.info("zkAuth", "Checking on-chain status for existing Google session...");
          
          const onChainCheck = await fetch("/api/zkauth/check-user-onchain", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email: googleUser.email }),
            credentials: "include",
          });
          
          const onChainData = await onChainCheck.json();
          
          if (onChainData.exists) {
            activityLogger.info("zkAuth", "User exists on-chain - auto-login...");
            setIsProcessing(true);
            setProcessingMessage("Reconstructing master key...");
            
            const loginResponse = await fetch("/api/zkauth/login", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ email: googleUser.email, googleUserId: googleUser.googleUserId }),
              credentials: "include",
            });
            
            const loginData = await loginResponse.json();
            setIsProcessing(false);
            
            await processLoginResponse(loginData, googleUser);
          } else {
            setShowSecretPhraseModal(true);
          }
        } catch (err) {
          console.error("[zkAuth] Reload check failed:", err);
        }
      })();
    }
  }, [googleUser, isLoggedIn, showSecretPhraseModal, twoFactorFlow.showMandatory2FASetup, twoFactorFlow.showEmailOtpModal, twoFactorFlow.showTotpModal, search, setIsProcessing, setProcessingMessage, setShowSecretPhraseModal, processLoginResponse]);
  
  const handleGoogleLogin = useCallback(() => {
    activityLogger.info("zkAuth", "Initiating Google OAuth...");
    window.location.href = "/api/oauth/google";
  }, []);
  
  const handleSecretPhraseSubmit = useCallback(async (submittedPhrase: string) => {
    if (!googleUser) {
      showAlert("error", "Error", "Not authenticated with Google");
      return;
    }

    try {
      setShowSecretPhraseModal(false);
      setIsProcessing(true);
      setProcessingMessage("Deriving private key...");
      activityLogger.info("zkAuth", "Deriving Ed25519 private key...");

      const privateKey = await derivePrivateKey(googleUser.googleUserId, submittedPhrase);
      activityLogger.success("zkAuth", "Private key derived successfully");

      setProcessingMessage("Creating zkAuth identity...");
      activityLogger.info("zkAuth", "Registering identity on 3 blockchains...");

      const registerResponse = await fetch("/api/zkauth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ 
          privateKey, 
          email: googleUser.email,
          googleUserId: googleUser.googleUserId
        }),
        credentials: "include",
      });

      const registerData = await registerResponse.json();

      if (!registerData.success) {
        throw new Error(registerData.error || "Registration failed");
      }

      await fetch("/api/oauth/google/complete-registration", {
        method: "POST",
        credentials: "include",
      });

      setProcessingMessage("Identity created successfully!");
      activityLogger.success("zkAuth", "zkAuth identity created - shares stored on Zcash, Starknet, Solana");
      
      setIsProcessing(false);
      
      if (googleUser?.googleUserId && googleUser?.email) {
        storeAuthUser({
          googleUserId: googleUser.googleUserId,
          email: googleUser.email,
          name: googleUser.name,
          picture: googleUser.picture,
          isRegistered: true,
          masterKeyDistributed: true,
        });
      }
      
      await refetchUser();
      
      activityLogger.info("zkAuth", "New user - requiring 2FA setup");
      isAwaiting2FARef.current = true;
      twoFactorFlow.setShowMandatory2FASetup(true);
      
    } catch (error) {
      console.error("[zkAuth] Registration error:", error);
      const errorMessage = error instanceof Error ? error.message : "Registration failed";
      activityLogger.error("zkAuth", `Registration failed: ${errorMessage}`);
      showAlert("error", "Registration Failed", errorMessage);
      setIsProcessing(false);
    }
  }, [googleUser, showAlert, setShowSecretPhraseModal, setIsProcessing, setProcessingMessage, refetchUser, twoFactorFlow]);
  
  return {
    googleUser,
    isLoggedIn,
    refetchUser,
    handleGoogleLogin,
    handleSecretPhraseSubmit,
    oauthFlowProcessedRef,
    reloadCheckDoneRef,
    isAwaiting2FARef,
    userDismissedAuthRef,
    twoFactorFlow,
  };
}

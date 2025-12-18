/**
 * useZkAuthSession - Hook for managing zkAuth OAuth session state
 * Extracts Google OAuth session management from home.tsx
 */
import { useRef, useEffect, useCallback } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useSearch } from 'wouter';
import { activityLogger } from '@/lib/activityLogger';

export interface GoogleUser {
  googleUserId: string;
  email: string;
  name: string;
  picture?: string;
  isRegistered: boolean;
  masterKeyDistributed?: boolean;
  verifiedAt?: string;
  lastSignIn?: string;
}

export interface UseZkAuthSessionReturn {
  googleUser: GoogleUser | null | undefined;
  isLoggedIn: boolean;
  refetchUser: () => Promise<unknown>;
  
  // Auth flow refs (exposed for external synchronization)
  oauthFlowProcessedRef: React.MutableRefObject<boolean>;
  reloadCheckDoneRef: React.MutableRefObject<boolean>;
  isAwaiting2FARef: React.MutableRefObject<boolean>;
  
  // OAuth callback handlers
  handleOAuthCallback: () => {
    isSuccess: boolean;
    error: string | null;
  };
  
  // Logout handler
  handleLogout: () => Promise<void>;
  
  // Login with Google
  handleGoogleLogin: () => void;
}

export function useZkAuthSession(): UseZkAuthSessionReturn {
  const search = useSearch();
  const queryClient = useQueryClient();
  
  // Auth flow refs
  const oauthFlowProcessedRef = useRef(false);
  const reloadCheckDoneRef = useRef(false);
  const isAwaiting2FARef = useRef(false);
  const prevIsLoggedInRef = useRef<boolean | undefined>(undefined);
  
  // Fetch Google user session
  const { data: googleUser, refetch: refetchUser } = useQuery<GoogleUser | null>({
    queryKey: ["/api/oauth/google/user"],
    queryFn: async () => {
      const response = await fetch("/api/oauth/google/user", { credentials: "include" });
      if (!response.ok) return null;
      const data = await response.json();
      if (!data.authenticated) return null;
      return {
        googleUserId: data.googleUserId,
        email: data.email,
        name: data.name,
        picture: data.picture,
        isRegistered: data.isRegistered,
        masterKeyDistributed: data.masterKeyDistributed,
      };
    },
  });
  
  const isLoggedIn = !!(googleUser?.isRegistered && googleUser?.masterKeyDistributed);
  
  // Reset auth flow refs when user logs out
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
  
  // Parse OAuth callback from URL
  const handleOAuthCallback = useCallback(() => {
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
      return { isSuccess: false, error: errorMessages[error] || "Login failed" };
    }
    
    return { isSuccess: oauthSuccess, error: null };
  }, [search]);
  
  // Logout handler
  const handleLogout = useCallback(async () => {
    try {
      await fetch("/api/oauth/google/logout", { method: "POST", credentials: "include" });
      await fetch("/api/zkauth/logout", { method: "POST", credentials: "include" });
      activityLogger.info("zkAuth", "User logged out successfully");
      queryClient.invalidateQueries({ queryKey: ["/api/oauth/google/user"] });
    } catch (err) {
      console.error("[zkAuth] Logout error:", err);
    }
  }, [queryClient]);
  
  // Start Google OAuth login
  const handleGoogleLogin = useCallback(() => {
    window.location.href = "/api/oauth/google";
  }, []);
  
  return {
    googleUser,
    isLoggedIn,
    refetchUser,
    oauthFlowProcessedRef,
    reloadCheckDoneRef,
    isAwaiting2FARef,
    handleOAuthCallback,
    handleLogout,
    handleGoogleLogin,
  };
}

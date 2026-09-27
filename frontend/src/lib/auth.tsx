import {
  createContext,
  useContext,
  useState,
  useEffect,
  useCallback,
  useRef,
  type ReactNode,
} from "react";
import { REFRESH_TOKEN_KEY, postRefresh, refreshSession } from "./refresh-token.ts";

export interface AuthUser {
  id: number;
  username: string;
  email: string;
  role: "admin" | "analyst" | "viewer";
}

interface AuthContextType {
  user: AuthUser | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  isDemo: boolean;
  login: (username: string, password: string) => Promise<void>;
  loginDemo: () => void;
  logout: () => void;
  getAccessToken: () => string | null;
  refreshAccessToken: () => Promise<string | null>;
}

const AuthContext = createContext<AuthContextType | null>(null);

const DEMO_MODE_KEY = "athena_demo_mode";

const DEMO_USER: AuthUser = {
  id: 0,
  username: "demo",
  email: "demo@mythos.ai",
  role: "admin",
};

function decodeJwtPayload(token: string): Record<string, unknown> {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new Error("Invalid JWT format");
  }
  const payload = parts[1];
  const base64 = payload.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), "=");
  const decoded = atob(padded);
  return JSON.parse(decoded);
}

function getExpirationFromToken(token: string): number | null {
  try {
    const payload = decodeJwtPayload(token);
    if (typeof payload.exp === "number") {
      return payload.exp;
    }
    return null;
  } catch {
    return null;
  }
}

function getUserIdFromToken(token: string): number | null {
  try {
    const payload = decodeJwtPayload(token);
    if (typeof payload.user_id === "number") {
      return payload.user_id;
    }
    if (typeof payload.sub === "number") {
      return payload.sub;
    }
    if (typeof payload.sub === "string") {
      const parsed = parseInt(payload.sub, 10);
      if (!isNaN(parsed)) return parsed;
    }
    return null;
  } catch {
    return null;
  }
}

async function fetchCurrentUser(accessToken: string): Promise<AuthUser> {
  const headers: Record<string, string> = {
    Authorization: `Bearer ${accessToken}`,
    "Content-Type": "application/json",
  };

  const meRes = await fetch("/api/accounts/users/me/", { headers });

  if (meRes.ok) {
    const data = await meRes.json();
    return {
      id: data.id,
      username: data.username,
      email: data.email ?? "",
      role: data.role ?? "viewer",
    };
  }

  if (meRes.status === 404) {
    const userId = getUserIdFromToken(accessToken);
    if (!userId) {
      throw new Error("Could not determine user ID from token");
    }

    const userRes = await fetch(`/api/accounts/users/${userId}/`, { headers });
    if (!userRes.ok) {
      throw new Error(`Failed to fetch user details: ${userRes.status}`);
    }

    const data = await userRes.json();
    return {
      id: data.id,
      username: data.username,
      email: data.email ?? "",
      role: data.role ?? "viewer",
    };
  }

  throw new Error(`Failed to fetch current user: ${meRes.status}`);
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isDemo, setIsDemo] = useState(false);
  const accessTokenRef = useRef<string | null>(null);
  const refreshTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const clearRefreshTimer = useCallback(() => {
    if (refreshTimerRef.current) {
      clearTimeout(refreshTimerRef.current);
      refreshTimerRef.current = null;
    }
  }, []);

  const scheduleTokenRefresh = useCallback(
    (accessToken: string) => {
      clearRefreshTimer();

      const exp = getExpirationFromToken(accessToken);
      if (!exp) return;

      const now = Math.floor(Date.now() / 1000);
      const timeUntilExpiry = exp - now;
      const refreshIn = Math.max((timeUntilExpiry - 60) * 1000, 0);

      refreshTimerRef.current = setTimeout(async () => {
        if (!localStorage.getItem(REFRESH_TOKEN_KEY)) return;

        // Another tab may refresh at the same moment: refreshSession removes
        // the stored token only if it is still the one this tab sent, and
        // follows a newer one another tab stored (refresh-token.ts).
        const outcome = await refreshSession(localStorage, postRefresh);
        if (outcome.kind === "refreshed") {
          accessTokenRef.current = outcome.access;
          scheduleTokenRefresh(outcome.access);
          return;
        }
        accessTokenRef.current = null;
        setUser(null);
      }, refreshIn);
    },
    [clearRefreshTimer],
  );

  // This tab's session ended because its refresh was refused. Unlike
  // logout(), the stored refresh token is not removed here: refreshSession has
  // already removed it if it was still this tab's, and left another tab's.
  const endSession = useCallback(() => {
    clearRefreshTimer();
    accessTokenRef.current = null;
    setUser(null);
    setIsDemo(false);
    localStorage.removeItem(DEMO_MODE_KEY);
  }, [clearRefreshTimer]);

  const logout = useCallback(() => {
    endSession();
    localStorage.removeItem(REFRESH_TOKEN_KEY);
  }, [endSession]);

  const loginDemo = useCallback(() => {
    clearRefreshTimer();
    accessTokenRef.current = null;
    localStorage.removeItem(REFRESH_TOKEN_KEY);
    localStorage.setItem(DEMO_MODE_KEY, "true");
    setIsDemo(true);
    setUser(DEMO_USER);
    setIsLoading(false);
  }, [clearRefreshTimer]);

  const login = useCallback(
    async (username: string, password: string) => {
      const res = await fetch("/api/token/", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });

      if (!res.ok) {
        const text = await res.text();
        throw new Error(text || `Login failed: ${res.status}`);
      }

      const data = await res.json();
      accessTokenRef.current = data.access;
      localStorage.setItem(REFRESH_TOKEN_KEY, data.refresh);
      localStorage.removeItem(DEMO_MODE_KEY);
      setIsDemo(false);

      const currentUser = await fetchCurrentUser(data.access);
      setUser(currentUser);

      scheduleTokenRefresh(data.access);
    },
    [scheduleTokenRefresh],
  );

  const getAccessToken = useCallback(() => {
    return accessTokenRef.current;
  }, []);

  const refreshAccessToken = useCallback(async (): Promise<string | null> => {
    if (!localStorage.getItem(REFRESH_TOKEN_KEY)) return null;

    const outcome = await refreshSession(localStorage, postRefresh);
    if (outcome.kind === "refreshed") {
      accessTokenRef.current = outcome.access;
      scheduleTokenRefresh(outcome.access);
      return outcome.access;
    }
    endSession();
    return null;
  }, [endSession, scheduleTokenRefresh]);

  useEffect(() => {
    let cancelled = false;

    async function tryRestoreSession() {
      if (localStorage.getItem(DEMO_MODE_KEY) === "true") {
        setIsDemo(true);
        setUser(DEMO_USER);
        setIsLoading(false);
        return;
      }

      if (!localStorage.getItem(REFRESH_TOKEN_KEY)) {
        setIsLoading(false);
        return;
      }

      try {
        // Several restored tabs refresh at once; refreshSession keeps the
        // session for all of them (refresh-token.ts).
        const outcome = await refreshSession(localStorage, postRefresh);
        if (outcome.kind !== "refreshed" || cancelled) return;

        accessTokenRef.current = outcome.access;
        const currentUser = await fetchCurrentUser(outcome.access);
        if (cancelled) return;

        setUser(currentUser);
        scheduleTokenRefresh(outcome.access);
      } catch {
        // The user could not be read. The refresh token is the new one the
        // refresh just stored, and still good: it stays, so the next load
        // restores the session.
      } finally {
        if (!cancelled) setIsLoading(false);
      }
    }

    tryRestoreSession();

    return () => {
      cancelled = true;
    };
  }, [scheduleTokenRefresh]);

  useEffect(() => {
    return () => {
      clearRefreshTimer();
    };
  }, [clearRefreshTimer]);

  return (
    <AuthContext.Provider
      value={{
        user,
        isAuthenticated: !!user,
        isLoading,
        isDemo,
        login,
        loginDemo,
        logout,
        getAccessToken,
        refreshAccessToken,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextType {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}

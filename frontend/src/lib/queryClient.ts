import { QueryClient, QueryFunction } from "@tanstack/react-query";

let getTokenFn: (() => string | null) | null = null;
let onRefreshFn: (() => Promise<string | null>) | null = null;
let onLogoutFn: (() => void) | null = null;

export function setTokenGetter(fn: () => string | null) {
  getTokenFn = fn;
}

export function setRefreshHandler(fn: () => Promise<string | null>) {
  onRefreshFn = fn;
}

export function setLogoutHandler(fn: () => void) {
  onLogoutFn = fn;
}

function isDemoMode(): boolean {
  try {
    return localStorage.getItem("athena_demo_mode") === "true";
  } catch {
    return false;
  }
}

function getAuthHeaders(): Record<string, string> {
  const headers: Record<string, string> = {};
  if (getTokenFn) {
    const token = getTokenFn();
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
  }
  return headers;
}

let refreshPromise: Promise<string | null> | null = null;

async function tryRefreshToken(): Promise<string | null> {
  if (!onRefreshFn) return null;
  if (refreshPromise) return refreshPromise;

  refreshPromise = onRefreshFn().finally(() => {
    refreshPromise = null;
  });

  return refreshPromise;
}

async function fetchWithAuth(url: string, init: RequestInit = {}): Promise<Response> {
  const headers = new Headers(init.headers);
  const authHeaders = getAuthHeaders();
  for (const [key, value] of Object.entries(authHeaders)) {
    headers.set(key, value);
  }

  const res = await fetch(url, { ...init, headers, credentials: "include" });

  if (res.status === 401 && onRefreshFn && !isDemoMode()) {
    const newToken = await tryRefreshToken();
    if (newToken) {
      headers.set("Authorization", `Bearer ${newToken}`);
      return fetch(url, { ...init, headers, credentials: "include" });
    }
    if (onLogoutFn) onLogoutFn();
  }

  return res;
}

async function throwIfResNotOk(res: Response) {
  if (!res.ok) {
    const text = (await res.text()) || res.statusText;
    throw new Error(`${res.status}: ${text}`);
  }
}

/**
 * Send a request and hand back whatever answered, refusals included, so the
 * caller can read each answer for what it is. `extra`: headers of its own (an
 * Idempotency-Key). A 401 refreshed and sent again carries them unchanged.
 */
export async function apiSend(
  method: string,
  url: string,
  data?: unknown | undefined,
  extra: Record<string, string> = {},
): Promise<Response> {
  const headers: Record<string, string> = { ...extra };
  if (data) {
    headers["Content-Type"] = "application/json";
  }

  return fetchWithAuth(url, {
    method,
    headers,
    body: data ? JSON.stringify(data) : undefined,
  });
}

export async function apiRequest(
  method: string,
  url: string,
  data?: unknown | undefined,
): Promise<Response> {
  const res = await apiSend(method, url, data);
  await throwIfResNotOk(res);
  return res;
}

type UnauthorizedBehavior = "returnNull" | "throw";
export const getQueryFn: <T>(options: {
  on401: UnauthorizedBehavior;
}) => QueryFunction<T> =
  ({ on401: unauthorizedBehavior }) =>
  async ({ queryKey }) => {
    const res = await fetchWithAuth(queryKey.join("/") as string);

    if (unauthorizedBehavior === "returnNull" && res.status === 401) {
      return null;
    }

    await throwIfResNotOk(res);
    return await res.json();
  };

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      queryFn: getQueryFn({ on401: "throw" }),
      refetchInterval: false,
      refetchOnWindowFocus: false,
      staleTime: Infinity,
      retry: false,
    },
    mutations: {
      retry: false,
    },
  },
});

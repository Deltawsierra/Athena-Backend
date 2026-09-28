/**
 * The refresh token every tab of this origin shares, and the one refresh that
 * spends it.
 *
 * The backend spends a refresh token exactly once (safety/refresh.py): of two
 * refreshes of one token, one is answered with a new token and the other 401
 * "refresh token already used". Every tab keeps the one token in localStorage,
 * and a browser restoring several tabs refreshes them at once. The losing tab
 * used to remove the stored token on its 401 -- by then, often the WINNER's
 * new token -- which signed the operator out of every tab: 11 of 20 two-tab
 * restores lost the session (round 4, M2).
 *
 * Now a refused refresh removes the stored token only if it is still the one
 * this tab sent (compare-and-remove), and re-reads storage first: another tab
 * may have stored a newer token, which this tab then refreshes with. And when
 * the refusal says the token was spent by another refresh, whose answer may
 * still be on its way to that tab, this tab waits a little for the newer token
 * to be stored before giving up. A refresh that gets no answer at all leaves
 * storage as it is.
 *
 * Round 5 (F4): with four or more tabs restoring at once, the losing tabs
 * chase each other down the single-use token chain -- each round one tab wins
 * a fresh token and the rest re-read and retry with it -- so a tab may need as
 * many rounds as there are tabs before it wins its own. The retry budget
 * (`attempts`) is large enough for a realistic tab count, so a contended tab
 * recovers from the stored newer token rather than being signed out once three
 * rounds are spent. And the wait for another tab's token is shorter, so a
 * spent-token 401 whose successor never comes (a lost refresh response) no
 * longer delays a stop by two seconds before the tab gives up -- while a newer
 * token that IS on its way is still picked up as soon as it is stored.
 *
 * Only erasable TypeScript here, so `node --test` runs the test beside it.
 */

export const REFRESH_TOKEN_KEY = "athena_refresh_token";

/** The code the backend answers a refresh token already spent with. */
export const SPENT_ELSEWHERE_CODE = "refresh_token_already_used";

/** localStorage, or anything shaped like it. */
export interface TokenStore {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

/** The backend's answer to one refresh. */
export interface RefreshAnswer {
  ok: boolean;
  status: number;
  body: unknown;
}

export type RefreshOutcome =
  | { kind: "refreshed"; access: string }
  | { kind: "signed-out" }
  | { kind: "unreachable" };

export interface RefreshOptions {
  /**
   * How many refreshes one call makes at most, following newer tokens. Each
   * round another tab has won a fresh token, so this is the largest number of
   * tabs contending at once that all recover their own session; past it a tab
   * is signed out and recovers on its next reload from the stored token.
   */
  attempts?: number;
  /** How long to wait for another tab's newer token after "already used". */
  waitForOtherTabMs?: number;
  /** How often storage is re-read while waiting. */
  pollMs?: number;
  sleep?: (ms: number) => Promise<void>;
}

const defaultSleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

/**
 * Remove the stored refresh token only if it is still `sent`, the token this
 * tab sent. Returns the token stored now: null when it was removed or there is
 * none, or another tab's newer one, which is left in place.
 */
export function forgetRefreshToken(store: TokenStore, sent: string): string | null {
  const stored = store.getItem(REFRESH_TOKEN_KEY);
  if (stored === sent) {
    store.removeItem(REFRESH_TOKEN_KEY);
    return null;
  }
  return stored;
}

function spentElsewhere(answer: RefreshAnswer): boolean {
  if (answer.status !== 401 || typeof answer.body !== "object" || answer.body === null) return false;
  const body = answer.body as { code?: unknown; detail?: unknown };
  return body.code === SPENT_ELSEWHERE_CODE || body.detail === "refresh token already used";
}

async function newerThan(
  store: TokenStore,
  sent: string,
  waitMs: number,
  pollMs: number,
  sleep: (ms: number) => Promise<void>,
): Promise<string | null> {
  for (let waited = 0; waited < waitMs; waited += pollMs) {
    await sleep(pollMs);
    const stored = store.getItem(REFRESH_TOKEN_KEY);
    if (stored !== sent) return stored;
  }
  return sent;
}

/**
 * Refresh the session with the stored refresh token, as one tab of several.
 *
 * - Answered with tokens: the new refresh token is stored, and the access
 *   token returned.
 * - Refused: storage is re-read. A newer token another tab stored is
 *   refreshed with instead. If the refusal is "already used" and nothing newer
 *   is stored yet, the other refresh's token may still be on its way: storage
 *   is re-read for up to `waitForOtherTabMs`. Otherwise the stored token is
 *   removed only if it is still the one sent (forgetRefreshToken).
 * - No answer (the request failed): storage is left as it is.
 */
export async function refreshSession(
  store: TokenStore,
  post: (refresh: string) => Promise<RefreshAnswer>,
  options: RefreshOptions = {},
): Promise<RefreshOutcome> {
  const attempts = options.attempts ?? 10;
  const waitMs = options.waitForOtherTabMs ?? 500;
  const pollMs = options.pollMs ?? 50;
  const sleep = options.sleep ?? defaultSleep;

  for (let attempt = 0; attempt < attempts; attempt++) {
    const sent = store.getItem(REFRESH_TOKEN_KEY);
    if (!sent) return { kind: "signed-out" };

    let answer: RefreshAnswer;
    try {
      answer = await post(sent);
    } catch {
      return { kind: "unreachable" };
    }

    if (answer.ok) {
      const body = (answer.body ?? {}) as { access?: unknown; refresh?: unknown };
      if (typeof body.refresh === "string") store.setItem(REFRESH_TOKEN_KEY, body.refresh);
      if (typeof body.access === "string") return { kind: "refreshed", access: body.access };
      return { kind: "signed-out" };
    }

    let stored = store.getItem(REFRESH_TOKEN_KEY);
    if (stored === sent && spentElsewhere(answer)) {
      stored = await newerThan(store, sent, waitMs, pollMs, sleep);
    }
    if (stored !== null && stored !== sent) continue;
    forgetRefreshToken(store, sent);
    return { kind: "signed-out" };
  }
  // Every one of the (many) attempts was overtaken by another tab's newer
  // token: more tabs contended at once than the budget, so this tab is signed
  // out for now, but the newest token stays stored and its next reload restores
  // the session from it.
  return { kind: "signed-out" };
}

/** POST /api/token/refresh/, as the backend answers it. */
export async function postRefresh(refresh: string): Promise<RefreshAnswer> {
  const res = await fetch("/api/token/refresh/", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ refresh }),
  });
  let body: unknown = null;
  try {
    body = await res.json();
  } catch {
    body = null;
  }
  return { ok: res.ok, status: res.status, body };
}

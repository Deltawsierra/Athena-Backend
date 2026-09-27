// Two tabs refreshing one session at once (round 4, M2). Run: npm test
// (node --test; Node 22.6 or later runs TypeScript directly).
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  REFRESH_TOKEN_KEY,
  forgetRefreshToken,
  refreshSession,
  type RefreshAnswer,
  type TokenStore,
} from "./refresh-token.ts";

/** localStorage, shared by every tab of the origin. */
class Storage implements TokenStore {
  items = new Map<string, string>();
  getItem(key: string): string | null {
    return this.items.has(key) ? (this.items.get(key) as string) : null;
  }
  setItem(key: string, value: string): void {
    this.items.set(key, value);
  }
  removeItem(key: string): void {
    this.items.delete(key);
  }
}

/**
 * The backend's refresh as safety/refresh.py makes it: each token is spent
 * exactly once, at the moment the request arrives; a spent token is 401
 * "refresh token already used", an unknown one 401 "token_not_valid". Each
 * answer is held until the test releases it, so the test picks the order the
 * tabs hear back in.
 */
class Backend {
  live = new Set<string>(["t0"]);
  spent = new Set<string>();
  issued = 0;
  held: Array<{ token: string; release: () => void }> = [];

  post = (refresh: string): Promise<RefreshAnswer> => {
    let answer: RefreshAnswer;
    if (this.live.has(refresh)) {
      this.live.delete(refresh);
      this.spent.add(refresh);
      const next = `t${++this.issued}`;
      this.live.add(next);
      answer = { ok: true, status: 200, body: { access: `a-${next}`, refresh: next } };
    } else if (this.spent.has(refresh)) {
      answer = { ok: false, status: 401, body: { detail: "refresh token already used", code: "refresh_token_already_used" } };
    } else {
      answer = { ok: false, status: 401, body: { detail: "Token is invalid", code: "token_not_valid" } };
    }
    return new Promise((resolve) => {
      this.held.push({ token: refresh, release: () => resolve(answer) });
    });
  };

  /** Let the answer to the request numbered `index` (in arrival order) through. */
  release(index: number): void {
    this.held[index].release();
  }
}

const tick = () => new Promise<void>((resolve) => setImmediate(resolve));

async function settle(): Promise<void> {
  for (let i = 0; i < 20; i++) await tick();
}

/** A sleep that moves time forward only as the test yields. */
const quickSleep = () => tick();

test("a refused refresh removes the stored token only if it is still the one this tab sent", () => {
  const store = new Storage();
  store.setItem(REFRESH_TOKEN_KEY, "mine");
  assert.equal(forgetRefreshToken(store, "mine"), null);
  assert.equal(store.getItem(REFRESH_TOKEN_KEY), null);
  store.setItem(REFRESH_TOKEN_KEY, "newer");
  assert.equal(forgetRefreshToken(store, "mine"), "newer");
  assert.equal(store.getItem(REFRESH_TOKEN_KEY), "newer");
});

test("two tabs refresh at once and the winner is answered first: both stay signed in", async () => {
  const store = new Storage();
  store.setItem(REFRESH_TOKEN_KEY, "t0");
  const backend = new Backend();
  const winner = refreshSession(store, backend.post, { sleep: quickSleep });
  const loser = refreshSession(store, backend.post, { sleep: quickSleep });
  await settle();
  assert.equal(backend.held.length, 2);
  backend.release(0); // t0 -> t1, stored
  await settle();
  backend.release(1); // t0 again: already used; t1 is stored, so the loser refreshes with it
  await settle();
  assert.equal(backend.held.length, 3);
  assert.equal(backend.held[2].token, "t1");
  backend.release(2);
  assert.deepEqual(await winner, { kind: "refreshed", access: "a-t1" });
  assert.deepEqual(await loser, { kind: "refreshed", access: "a-t2" });
  assert.equal(store.getItem(REFRESH_TOKEN_KEY), "t2");
  assert.ok(backend.live.has("t2"), "the stored token is the live one");
});

test("two tabs refresh at once and the loser is answered first: it waits for the winner's token", async () => {
  const store = new Storage();
  store.setItem(REFRESH_TOKEN_KEY, "t0");
  const backend = new Backend();
  const winner = refreshSession(store, backend.post, { sleep: quickSleep, waitForOtherTabMs: 5000 });
  const loser = refreshSession(store, backend.post, { sleep: quickSleep, waitForOtherTabMs: 5000 });
  await settle();
  backend.release(1); // the loser hears "already used" while t0 is still stored
  await settle();
  assert.equal(store.getItem(REFRESH_TOKEN_KEY), "t0", "the loser did not remove the token the winner is spending");
  backend.release(0); // the winner stores t1
  await settle();
  assert.equal(backend.held.length, 3);
  backend.release(2); // the loser refreshes with t1
  assert.deepEqual(await winner, { kind: "refreshed", access: "a-t1" });
  assert.deepEqual(await loser, { kind: "refreshed", access: "a-t2" });
  assert.equal(store.getItem(REFRESH_TOKEN_KEY), "t2");
  assert.ok(backend.live.has("t2"));
});

test("twenty two-tab restores in both orders lose no session", async () => {
  for (let trial = 0; trial < 20; trial++) {
    const store = new Storage();
    store.setItem(REFRESH_TOKEN_KEY, "t0");
    const backend = new Backend();
    const tabs = [0, 1].map(() => refreshSession(store, backend.post, { sleep: quickSleep, waitForOtherTabMs: 5000 }));
    await settle();
    const first = trial % 2;
    backend.release(first);
    await settle();
    backend.release(1 - first);
    await settle();
    for (let i = 0; i < 200 && backend.held.length < 3; i++) await tick();
    assert.equal(backend.held.length, 3, `trial ${trial}: the second tab refreshes with the first tab's new token`);
    backend.release(2);
    const outcomes = await Promise.all(tabs);
    assert.deepEqual(outcomes.map((o) => o.kind), ["refreshed", "refreshed"], `trial ${trial}`);
    const stored = store.getItem(REFRESH_TOKEN_KEY);
    assert.ok(stored !== null && backend.live.has(stored), `trial ${trial}: the stored token refreshes`);
  }
});

test("a token that is not valid is removed at once, without waiting", async () => {
  const store = new Storage();
  store.setItem(REFRESH_TOKEN_KEY, "expired");
  const backend = new Backend();
  let slept = 0;
  const outcome = refreshSession(store, backend.post, { sleep: async () => void slept++ });
  await settle();
  backend.release(0);
  assert.deepEqual(await outcome, { kind: "signed-out" });
  assert.equal(store.getItem(REFRESH_TOKEN_KEY), null);
  assert.equal(slept, 0);
});

test("a token spent with no other tab to store a newer one is removed after the wait", async () => {
  const store = new Storage();
  store.setItem(REFRESH_TOKEN_KEY, "t0");
  const backend = new Backend();
  backend.live.delete("t0");
  backend.spent.add("t0");
  let slept = 0;
  const outcome = refreshSession(store, backend.post, {
    sleep: async () => void slept++,
    waitForOtherTabMs: 500,
    pollMs: 50,
  });
  await settle();
  backend.release(0);
  assert.deepEqual(await outcome, { kind: "signed-out" });
  assert.equal(slept, 10);
  assert.equal(store.getItem(REFRESH_TOKEN_KEY), null);
});

test("a refresh that gets no answer leaves storage as it is", async () => {
  const store = new Storage();
  store.setItem(REFRESH_TOKEN_KEY, "t0");
  const outcome = await refreshSession(store, () => Promise.reject(new TypeError("Failed to fetch")));
  assert.deepEqual(outcome, { kind: "unreachable" });
  assert.equal(store.getItem(REFRESH_TOKEN_KEY), "t0");
});

// An Idempotency-Key per user action (Phase 4, wave 2). Run: npm test
// (node --test; Node 22.6 or later runs TypeScript directly).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

import {
  IDEMPOTENCY_HEADER,
  REPLAYED_HEADER,
  actionFor,
  newKey,
  readKeyedAnswer,
  sendKeyed,
  stillPending,
  type KeyedAction,
  type KeyedAnswer,
  type SentAnswer,
} from "./idempotency.ts";

function headersOf(values: Record<string, string>): { get(name: string): string | null } {
  const lower = new Map(Object.entries(values).map(([name, value]) => [name.toLowerCase(), value]));
  return { get: (name: string) => lower.get(name.toLowerCase()) ?? null };
}

function sent(status: number, body: unknown, headers: Record<string, string> = {}): SentAnswer {
  const text = typeof body === "string" ? body : JSON.stringify(body);
  return { status, headers: headersOf(headers), text: async () => text };
}

/**
 * POST /api/pentest/scan/ behind the backend's key layer (idempotency/layer.py):
 * the first request with a key is recorded before the route runs and answered
 * with what the route answered; the same key and request again is that answer,
 * replayed; the same key while the first has not answered is 409 unknown; the
 * same key with another request is 422. Every scan the route starts is counted.
 * `lose` makes the next answer vanish after the backend has acted on it, as a
 * connection that drops on the way back does; `hold` keeps the next request
 * running until the test releases it.
 */
class Backend {
  scans = 0;
  records = new Map<string, { request: string; answer: SentAnswer | null }>();
  keysSeen: Array<string | null> = [];
  lose = false;
  hold: { release: () => void } | null = null;

  async send(request: unknown, headers: Record<string, string>): Promise<SentAnswer> {
    const key = headers[IDEMPOTENCY_HEADER] ?? null;
    this.keysSeen.push(key);
    const text = JSON.stringify(request);
    if (key !== null) {
      const earlier = this.records.get(key);
      if (earlier && earlier.request !== text) {
        return sent(422, { detail: "used for a different request", idempotency: { state: "done" } });
      }
      if (earlier && earlier.answer === null) {
        return sent(409, { detail: "its outcome is unknown", idempotency: { state: "in_flight" } });
      }
      if (earlier && earlier.answer !== null) {
        const replay = earlier.answer;
        return { ...replay, headers: headersOf({ [REPLAYED_HEADER]: "true" }) };
      }
      this.records.set(key, { request: text, answer: null });
    }
    this.scans += 1;
    const answer = sent(200, { scan_id: `scan-${this.scans}`, result: { findings: [] } });
    if (this.hold) {
      await new Promise<void>((release) => {
        this.hold = { release };
      });
    }
    if (key !== null) this.records.set(key, { request: text, answer });
    if (this.lose) {
      this.lose = false;
      throw new TypeError("Failed to fetch");
    }
    return answer;
  }
}

/** What the pentest page does on a press of Start Scan, without the page. */
async function press(backend: Backend, pending: { current: KeyedAction | null }, request: unknown) {
  const action = actionFor(pending.current, request);
  pending.current = action;
  const answer = await sendKeyed(action, (headers) => backend.send(request, headers));
  pending.current = stillPending(action, answer);
  return { action, answer };
}

const REQUEST = { url: "https://app.customer.example/", consent: true, scan_type: "quick", max_pages: 3 };

test("a lost answer, then the same press again, starts one scan and reads the first answer", async () => {
  const backend = new Backend();
  const pending = { current: null as KeyedAction | null };

  backend.lose = true;
  const first = await press(backend, pending, REQUEST);
  assert.equal(first.answer.kind, "unknown", "no answer arrived, so the outcome is unknown");
  assert.equal(pending.current, first.action, "the action is kept, with its key");

  const again = await press(backend, pending, REQUEST);
  assert.equal(backend.scans, 1, `the same press sent twice started ${backend.scans} scans`);
  assert.equal(backend.keysSeen.length, 2);
  assert.equal(backend.keysSeen[0], first.action.key);
  assert.equal(backend.keysSeen[1], first.action.key, "the second send carried the same key");
  assert.equal(again.answer.kind, "answered");
  assert.ok(again.answer.kind === "answered" && again.answer.replayed, "the second answer is the replay");
  assert.deepEqual(again.answer.kind === "answered" && again.answer.body, {
    scan_id: "scan-1",
    result: { findings: [] },
  });
  assert.equal(pending.current, null, "answered: the action is let go");
});

test("a press while the first is still running is told unknown, and starts nothing", async () => {
  const backend = new Backend();
  const pending = { current: null as KeyedAction | null };

  backend.hold = { release: () => undefined };
  const running = press(backend, pending, REQUEST);
  await new Promise((resolve) => setTimeout(resolve, 10));
  const meanwhile = await press(backend, pending, REQUEST);
  assert.equal(meanwhile.answer.kind, "unknown");
  assert.ok(meanwhile.answer.kind === "unknown" && meanwhile.answer.answerLater);
  assert.equal(meanwhile.action.key, backend.keysSeen[0], "sent again with the same key");
  backend.hold?.release();
  const first = await running;

  assert.equal(first.answer.kind, "answered");
  assert.equal(backend.scans, 1, `a press while the first was running started ${backend.scans} scans`);
});

test("a new action never reuses a key", () => {
  let n = 0;
  const makeKey = () => `key-${++n}`;
  const one = actionFor(null, REQUEST, makeKey);
  const other = actionFor(one, { ...REQUEST, url: "https://other.customer.example/" }, makeKey);
  const fresh = actionFor(null, REQUEST, makeKey);

  assert.notEqual(other.key, one.key, "another request is another action");
  assert.notEqual(fresh.key, one.key, "the same request after an answer is a new action");
  assert.equal(actionFor(one, REQUEST, makeKey), one, "the same request while unresolved is the same action");
});

test("without a key, the same press sent twice would start two scans", async () => {
  // What the page did before: the backend is unchanged without a key.
  const backend = new Backend();
  await backend.send(REQUEST, {});
  await backend.send(REQUEST, {});
  assert.equal(backend.scans, 2);
});

test("each answer is read for what it is", () => {
  const cases: Array<[string, number, Record<string, string>, unknown, Partial<KeyedAnswer>]> = [
    ["answered", 200, {}, { scan_id: "s" }, { kind: "answered", replayed: false }],
    ["a replay of a 202", 202, { [REPLAYED_HEADER]: "true" }, { scan_id: "s" }, { kind: "answered", replayed: true }],
    ["the first send still running", 409, {}, { detail: "d", idempotency: { state: "in_flight" } }, { kind: "unknown" }],
    ["the first send raised", 409, {}, { detail: "d", idempotency: { state: "unknown" } }, { kind: "unknown" }],
    ["the route's own 409", 409, {}, { error: "not the approved deployment" }, { kind: "refused" }],
    ["the same key, another request", 422, {}, { detail: "d", idempotency: { state: "done" } }, { kind: "bug" }],
    ["the route's own 422", 422, {}, { url: ["bad"] }, { kind: "refused" }],
    ["a key the backend cannot read", 400, {}, { detail: `${IDEMPOTENCY_HEADER} must be 1 to 255 ...` }, { kind: "bug" }],
    ["the route's own 400", 400, {}, { error: "bad recipient" }, { kind: "refused" }],
    ["the backend's own 502", 502, {}, { scan_id: "s", status: "failed", error: "e" }, { kind: "refused" }],
    ["a gateway's 504", 504, {}, "<html>Gateway Timeout</html>", { kind: "unknown" }],
  ];
  for (const [what, status, headers, body, expected] of cases) {
    const text = typeof body === "string" ? body : JSON.stringify(body);
    const answer = readKeyedAnswer(status, headersOf(headers), text);
    for (const [field, value] of Object.entries(expected)) {
      assert.equal((answer as Record<string, unknown>)[field], value, `${what}: ${field}`);
    }
  }
});

test("an unknown outcome keeps the action only while sending it again can be answered", () => {
  const action: KeyedAction = { key: "k", request: "{}" };
  const running = readKeyedAnswer(409, headersOf({}), JSON.stringify({ idempotency: { state: "in_flight" } }));
  const raised = readKeyedAnswer(409, headersOf({}), JSON.stringify({ idempotency: { state: "unknown" } }));
  const lost = readKeyedAnswer(504, headersOf({}), "Gateway Timeout");

  assert.equal(stillPending(action, running), action);
  assert.equal(stillPending(action, lost), action);
  assert.equal(stillPending(action, raised), null, "the same key would be told unknown until it expires");
  assert.equal(stillPending(action, readKeyedAnswer(200, headersOf({}), "{}")), null);
  assert.equal(stillPending(action, readKeyedAnswer(403, headersOf({}), "{}")), null);
});

test("a key is a UUID, with or without crypto.randomUUID", () => {
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
  assert.match(newKey(), uuid);
  const insecure = { getRandomValues: crypto.getRandomValues.bind(crypto) };
  assert.match(newKey(insecure), uuid);
  assert.notEqual(newKey(insecure), newKey(insecure));
});

// --- Every caller of a keyed route sends a key, and nothing else does -------

const SOURCE = join(import.meta.dirname, "..");
/** The four routes the backend's key layer is on (idempotency.layer.ROUTES). */
const KEYED_ROUTES = [
  /\/api\/pentest\/scan\//,
  /\/api\/pentest\/llm-scan\//,
  /\/api\/pentest\/scans\/[^"'`]*\/email\//,
  /\/api\/assurance\/deployments\/[^"'`]*\/connectors\/[^"'`]*\/push\//,
];

function sources(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) return sources(path);
    return /\.tsx?$/.test(name) && !/\.test\.tsx?$/.test(name) ? [path] : [];
  });
}

test("every call to a keyed route goes through sendKeyed, and sendKeyed goes to no other route", () => {
  let callers = 0;
  for (const path of sources(SOURCE)) {
    const text = readFileSync(path, "utf8");
    const literals = Array.from(text.matchAll(/(["'`])(\/api\/[^"'`]*)\1/g), (match) => match[2]);
    const keyed = literals.filter((literal) => KEYED_ROUTES.some((route) => route.test(literal)));
    const sends = Array.from(
      text.matchAll(/sendKeyed\(\s*\w+\s*,\s*\(headers\)\s*=>\s*apiSend\(\s*"POST"\s*,\s*(["'`])([^"'`]*)\1/g),
      (match) => match[2],
    );
    callers += keyed.length;
    assert.deepEqual(sends.sort(), keyed.sort(), `${path}: a keyed route sent without its key, or a key sent elsewhere`);
    for (const route of sends) {
      assert.ok(KEYED_ROUTES.some((keyedRoute) => keyedRoute.test(route)), `${path}: a key sent to ${route}`);
    }
  }
  assert.ok(callers >= 1, "found no caller of a keyed route: the scan is reading the wrong place");
});

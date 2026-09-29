// An Idempotency-Key per user action, on the backend routes that start
// something outside it (idempotency/layer.py): a scan launch, an LLM scan
// launch, a report resent, a finding pushed to a tracker.
//
// One press of a button is one action, and gets one key (crypto.randomUUID).
// Sending that action again -- because its answer never arrived -- is the same
// action, so it carries the same key, and the backend answers it from its
// record instead of starting a second scan. A new action never reuses a key.
//
// What the backend can answer, and what each means here:
//   2xx                        answered. With `Idempotent-Replayed: true` it is
//                              the answer the FIRST send got: the original
//                              answer, not a new start.
//   409 with `idempotency`     the first send has not recorded an answer, so
//                              whether it started is unknown. Never re-sent
//                              with a new key: the person is told to check the
//                              scans list, and may send the same action again.
//   422 with `idempotency`     the same key with a different request: a bug here.
//   400 "Idempotency-Key ..."  a key the backend cannot read: a bug here.
//   anything else              the route's own answer, as it always was.
// No answer at all (the connection failed, or a gateway answered in the
// backend's place) is unknown too: the action is kept, with its key.

export const IDEMPOTENCY_HEADER = "Idempotency-Key";
export const REPLAYED_HEADER = "Idempotent-Replayed";

/** One user action: the key it is sent with, and the request it is. */
export interface KeyedAction {
  key: string;
  request: string;
}

/** A new key: crypto.randomUUID where the page has it (a secure context), a
 * UUID v4 from crypto.getRandomValues where it does not. */
export function newKey(
  source: Pick<Crypto, "getRandomValues"> & { randomUUID?: () => string } = globalThis.crypto,
): string {
  if (typeof source.randomUUID === "function") return source.randomUUID();
  const bytes = source.getRandomValues(new Uint8Array(16));
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/**
 * The action a press sends. While an earlier action's outcome is unknown, a
 * press asking for exactly its request again is that action sent again, with
 * its key. Anything else is a new action with a new key.
 */
export function actionFor(
  pending: KeyedAction | null,
  request: unknown,
  makeKey: () => string = () => newKey(),
): KeyedAction {
  const text = JSON.stringify(request);
  if (pending !== null && pending.request === text) return pending;
  return { key: makeKey(), request: text };
}

/**
 * `unknown.answerLater`: whether sending the same action again can still read
 * its answer -- true while the first send may be running or never arrived;
 * false once the backend says the first send raised before it recorded one
 * (the same key would be told "unknown" until it expires).
 */
export type KeyedAnswer =
  | { kind: "answered"; status: number; replayed: boolean; body: unknown }
  | { kind: "unknown"; status: number | null; detail: string; answerLater: boolean }
  | { kind: "bug"; status: number; detail: string }
  | { kind: "refused"; status: number; body: unknown; text: string };

/** The action to keep after an answer: kept while sending it again can still
 * read its answer, so that send carries the same key; let go once the backend
 * has answered, or has said the same key can never be answered. */
export function stillPending(action: KeyedAction, answer: KeyedAnswer): KeyedAction | null {
  return answer.kind === "unknown" && answer.answerLater ? action : null;
}

function parsed(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function objectOf(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

/** What one answer to a keyed request says (the header comment). */
export function readKeyedAnswer(
  status: number,
  headers: { get(name: string): string | null },
  text: string,
): KeyedAnswer {
  const body = parsed(text);
  const fields = objectOf(body);
  const detail = typeof fields?.detail === "string" ? fields.detail : "";
  const record = objectOf(fields?.idempotency);
  if (status >= 200 && status < 300) {
    return { kind: "answered", status, replayed: headers.get(REPLAYED_HEADER) === "true", body };
  }
  if (status === 409 && record !== null) {
    return {
      kind: "unknown",
      status,
      detail: detail || "its outcome is unknown",
      answerLater: record.state !== "unknown",
    };
  }
  if ((status === 422 && record !== null) || (status === 400 && detail.startsWith(IDEMPOTENCY_HEADER))) {
    return { kind: "bug", status, detail: detail || text };
  }
  if (status >= 500 && fields === null) {
    // Not the backend's own answer (it answers JSON): a gateway's, or a crash
    // before the backend could answer. Whether anything started is unknown.
    return {
      kind: "unknown",
      status,
      detail: `no answer from the backend arrived (${status})`,
      answerLater: true,
    };
  }
  return { kind: "refused", status, body, text };
}

/** An answer as fetch gives it: enough to read it. */
export interface SentAnswer {
  status: number;
  headers: { get(name: string): string | null };
  text(): Promise<string>;
}

/** Send `action` with its key through `send`, and read what came back. A send
 * that never answers, or an answer that cannot be read, is unknown. */
export async function sendKeyed(
  action: KeyedAction,
  send: (headers: Record<string, string>) => Promise<SentAnswer>,
): Promise<KeyedAnswer> {
  let answer: SentAnswer;
  try {
    answer = await send({ [IDEMPOTENCY_HEADER]: action.key });
  } catch (error) {
    const why = error instanceof Error ? error.message : String(error);
    return { kind: "unknown", status: null, detail: `no answer arrived (${why})`, answerLater: true };
  }
  let text: string;
  try {
    text = await answer.text();
  } catch (error) {
    const why = error instanceof Error ? error.message : String(error);
    return {
      kind: "unknown",
      status: answer.status,
      detail: `the answer could not be read (${why})`,
      answerLater: true,
    };
  }
  return readKeyedAnswer(answer.status, answer.headers, text);
}

// Shared types and helpers of the cross-implementation test suite.
import { createHash } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export const TESTS = join(dirname(fileURLToPath(import.meta.url)), "..");
export const ROOT = join(TESTS, "..");
export const OUT = process.env.SSENC_TEST_OUT ?? join(TESTS, "out");
export const KEYS = join(TESTS, "keys");
export const VECTORS = join(TESTS, "vectors");

/** Cheap Argon2id cost used by the matrix so the KDF does not dominate the run. */
export const CHEAP_KDF = "m=8192,t=1,p=1";
export const PASSWORD = "correct horse battery staple ✓";
export const NEW_PASSWORD = "a different pass phrase";

export type ErrorKind = "USAGE" | "AUTH" | "MALFORMED" | "ENV";
export type ResultKind = "OK" | ErrorKind | "CRASH";

/** Keys for an operation: a password and/or names of keys in tests/keys/. */
export type KeySpec = { password?: string; ssh?: string[] };

export type EncryptOpts = {
  mode?: "lines" | "blob"; ws?: boolean; pad?: number; chunk?: number; kdf?: string; seal?: boolean;
  previous?: Buffer;
};

export type Op =
  | { cmd: "encrypt"; input: Buffer; key: KeySpec; opts: EncryptOpts; noAgent?: boolean }
  | { cmd: "decrypt"; input: Buffer; key: KeySpec; noAgent?: boolean }
  | { cmd: "rekey"; input: Buffer; key: KeySpec; newKey: KeySpec; kdf?: string; rewrapOnly?: boolean }
  | { cmd: "inspect"; input: Buffer };

export type OpResult = { kind: ResultKind; output: Buffer; stderr: string; ms: number };

export interface Participant {
  id: string;
  /** Human description shown in the report. */
  what: string;
  where: "server" | "browser";
  how: string;
  run(op: Op): Promise<OpResult>;
  close(): Promise<void>;
}

export type Status = "pass" | "fail" | "skipped";

export type Outcome = { status: Status; ms?: number; detail?: string; expected?: string; actual?: string; artifact?: string };

/** One planned check. Everything except `run` is written to checks.json before anything runs. */
export type Check = {
  id: string;
  suite: "unit" | "encrypt" | "cross" | "vectors" | "rekey" | "diff" | "negative";
  title: string;
  producer?: string;
  consumer?: string;
  /** rekey suite: the participant that did the rekey. */
  via?: string;
  case?: string;
  fixture?: string;
  mode?: string;
  key?: string;
  run: () => Promise<Outcome>;
};

export function sha256(b: Uint8Array): string {
  return createHash("sha256").update(b).digest("hex");
}

export function tail(s: string, n = 600): string {
  s = s.trim();
  return s.length > n ? "…" + s.slice(s.length - n) : s;
}

/** Limits how many async jobs run at once. */
export function limiter(max: number): <T>(job: () => Promise<T>) => Promise<T> {
  let active = 0;
  const waiting: (() => void)[] = [];
  return async <T>(job: () => Promise<T>): Promise<T> => {
    if (active >= max) await new Promise<void>((r) => waiting.push(r));
    active++;
    try {
      return await job();
    } finally {
      active--;
      waiting.shift()?.();
    }
  };
}

/** Compares a decrypt result with the expected plaintext. */
export function compareOutput(r: OpResult, expected: Buffer): Outcome {
  if (r.kind !== "OK") return { status: "fail", ms: r.ms, detail: "decrypt failed with " + r.kind + ": " + tail(r.stderr) };
  const want = sha256(expected);
  const got = sha256(r.output);
  if (want !== got) {
    return { status: "fail", ms: r.ms, expected: want, actual: got, detail: "output differs from the original (" + r.output.length + " bytes, expected " + expected.length + ")" };
  }
  return { status: "pass", ms: r.ms };
}

export function expectKind(r: OpResult, kind: ResultKind): Outcome {
  if (r.kind === kind) return { status: "pass", ms: r.ms, detail: r.kind === "OK" ? "" : tail(r.stderr, 200) };
  return { status: "fail", ms: r.ms, expected: kind, actual: r.kind, detail: "expected " + kind + ", got " + r.kind + (r.stderr ? ": " + tail(r.stderr) : "") };
}

/** Local time as YYYY-MM-DD HH:ii:ss. */
export function timestamp(d = new Date()): string {
  const p = (n: number): string => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

/** Makes console.log / console.error prefix every line they print with a timestamp. */
export function timestampConsole(): void {
  for (const name of ["log", "error"] as const) {
    const original = console[name].bind(console);
    console[name] = (...args: unknown[]): void => {
      const text = args.map((a) => (typeof a === "string" ? a : a instanceof Error ? a.stack ?? String(a) : JSON.stringify(a))).join(" ");
      original(text.split("\n").map((line) => timestamp() + " " + line).join("\n"));
    };
  }
}

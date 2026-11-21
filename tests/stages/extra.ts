// Stage 4: known-answer vectors, rekey chains, diff stability, negative tests.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { Check, KeySpec, OpResult, Participant } from "../lib/common.ts";
import { CHEAP_KDF, NEW_PASSWORD, PASSWORD, VECTORS, compareOutput, expectKind, tail } from "../lib/common.ts";
import { fixture } from "../lib/fixtures.ts";
import { readArtifact } from "./cross.ts";

type Vector = { name: string; key: { password?: string; ssh?: string } };
const vectors: Vector[] = JSON.parse(readFileSync(join(VECTORS, "vectors.json"), "utf8"));
const vectorKey = (v: Vector): KeySpec => (v.key.password !== undefined ? { password: v.key.password } : { ssh: [v.key.ssh as string] });
const vectorFile = (name: string, file: string): Buffer => readFileSync(join(VECTORS, name, file));

export function vectorChecks(all: Participant[]): Check[] {
  const checks: Check[] = [];
  for (const p of all) {
    for (const v of vectors) {
      const key = vectorKey(v);
      const keyLabel = v.key.password !== undefined ? "password" : (v.key.ssh as string).replace("test_", "ssh-");
      checks.push({
        id: "vectors." + p.id + "." + v.name + ".decrypt", suite: "vectors", title: p.id + " decrypts vector " + v.name,
        consumer: p.id, case: v.name, mode: "decrypt", key: keyLabel,
        run: async () => compareOutput(await p.run({ cmd: "decrypt", input: vectorFile(v.name, "encrypted.txt"), key }), vectorFile(v.name, "plain.bin")),
      });
      checks.push({
        id: "vectors." + p.id + "." + v.name + ".reencrypt", suite: "vectors", title: p.id + " re-encrypts vector " + v.name + " to identical bytes",
        consumer: p.id, case: v.name, mode: "re-encrypt", key: keyLabel,
        run: async () => {
          const enc = vectorFile(v.name, "encrypted.txt");
          const out = compareOutput(await p.run({ cmd: "encrypt", input: vectorFile(v.name, "plain.bin"), key, opts: { previous: enc } }), enc);
          if (out.status === "fail" && out.expected) out.detail = "re-encryption with the vector's own header is not byte-identical";
          return out;
        },
      });
    }
  }
  return checks;
}

const REKEY_CASE = "text-lf.lines-ws1.password";
const REKEY_SSH_CASE = "text-lf.lines-ws1.ssh-rsa";

const bodyOf = (b: Buffer): string => b.toString("latin1").split("\n").filter((l) => !l.startsWith("#slot ")).join("\n");

export function rekeyChecks(all: Participant[]): Check[] {
  const checks: Check[] = [];
  const plain = fixture("text-lf").data;
  const memo = new Map<string, Promise<OpResult>>();
  const rekeyed = (a: Participant, b: Participant, caseId: string, oldKey: KeySpec, newKey: KeySpec, rewrapOnly: boolean): Promise<OpResult> => {
    const k = [a.id, b.id, caseId, JSON.stringify(newKey), rewrapOnly].join("|");
    let r = memo.get(k);
    if (!r) {
      const src = readArtifact(a.id, caseId);
      r = src
        ? b.run({ cmd: "rekey", input: src, key: oldKey, newKey, kdf: CHEAP_KDF, rewrapOnly })
        : Promise.resolve({ kind: "CRASH" as const, output: Buffer.alloc(0), stderr: "no encrypted file from " + a.id, ms: 0 });
      memo.set(k, r);
    }
    return r;
  };
  for (const a of all) {
    for (const b of all) {
      for (const mode of ["rotate", "rewrap"] as const) {
        const rewrap = mode === "rewrap";
        for (const c of all) {
          checks.push({
            id: "rekey." + mode + "." + a.id + "." + b.id + "." + c.id, suite: "rekey",
            title: "rekey (" + mode + "): " + a.id + " encrypts → " + b.id + " rekeys → " + c.id + " decrypts",
            producer: a.id, via: b.id, consumer: c.id, mode, key: "password → password",
            run: async () => {
              const r = await rekeyed(a, b, REKEY_CASE, { password: PASSWORD }, { password: NEW_PASSWORD }, rewrap);
              if (r.kind !== "OK") return { status: "fail", ms: r.ms, detail: "rekey by " + b.id + " failed with " + r.kind + ": " + tail(r.stderr) };
              const original = readArtifact(a.id, REKEY_CASE) as Buffer;
              const sameBody = bodyOf(original) === bodyOf(r.output);
              if (rewrap && !sameBody) return { status: "fail", detail: "rewrap-only changed bytes outside the slot lines" };
              if (!rewrap && sameBody) return { status: "fail", detail: "rotate did not change the encrypted body" };
              return compareOutput(await c.run({ cmd: "decrypt", input: r.output, key: { password: NEW_PASSWORD } }), plain);
            },
          });
        }
        checks.push({
          id: "rekey-old." + mode + "." + a.id + "." + b.id, suite: "rekey",
          title: "rekey (" + mode + "): old password is rejected after " + b.id + " rekeys a file of " + a.id,
          producer: a.id, via: b.id, consumer: b.id, mode: mode + ", old key rejected", key: "password → password",
          run: async () => {
            const r = await rekeyed(a, b, REKEY_CASE, { password: PASSWORD }, { password: NEW_PASSWORD }, rewrap);
            if (r.kind !== "OK") return { status: "fail", detail: "rekey failed with " + r.kind + ": " + tail(r.stderr) };
            return expectKind(await b.run({ cmd: "decrypt", input: r.output, key: { password: PASSWORD } }), "AUTH");
          },
        });
      }
      checks.push({
        id: "rekey-switch.pw-ssh." + a.id + "." + b.id, suite: "rekey",
        title: "rekey password → ssh-ed25519: " + a.id + " encrypts → " + b.id + " rekeys → " + a.id + " decrypts",
        producer: a.id, via: b.id, consumer: a.id, mode: "rotate, key type switch", key: "password → ssh-ed25519",
        run: async () => {
          const r = await rekeyed(a, b, REKEY_CASE, { password: PASSWORD }, { ssh: ["test_ed25519"] }, false);
          if (r.kind !== "OK") return { status: "fail", ms: r.ms, detail: "rekey failed with " + r.kind + ": " + tail(r.stderr) };
          return compareOutput(await a.run({ cmd: "decrypt", input: r.output, key: { ssh: ["test_ed25519"] } }), plain);
        },
      });
      checks.push({
        id: "rekey-switch.ssh-pw." + a.id + "." + b.id, suite: "rekey",
        title: "rekey ssh-rsa → password (rewrap): " + a.id + " encrypts → " + b.id + " rekeys → " + a.id + " decrypts",
        producer: a.id, via: b.id, consumer: a.id, mode: "rewrap, key type switch", key: "ssh-rsa → password",
        run: async () => {
          const r = await rekeyed(a, b, REKEY_SSH_CASE, { ssh: ["test_rsa"] }, { password: NEW_PASSWORD }, true);
          if (r.kind !== "OK") return { status: "fail", ms: r.ms, detail: "rekey failed with " + r.kind + ": " + tail(r.stderr) };
          return compareOutput(await a.run({ cmd: "decrypt", input: r.output, key: { password: NEW_PASSWORD } }), plain);
        },
      });
    }
  }
  return checks;
}

export function diffChecks(all: Participant[]): Check[] {
  const checks: Check[] = [];
  const original = fixture("text-lf").data.toString("utf8");
  const changedLine = original.split("\n").findIndex((l) => l.includes("port: 5432"));
  const changed = Buffer.from(original.replace("port: 5432", "port: 6543"));
  for (const a of all) {
    for (const b of all) {
      checks.push({
        id: "diff." + a.id + "." + b.id, suite: "diff",
        title: "one changed line → one changed encrypted line: " + a.id + " encrypts, " + b.id + " re-encrypts",
        producer: a.id, consumer: b.id, mode: "lines-ws1", key: "password",
        run: async () => {
          const first = readArtifact(a.id, REKEY_CASE);
          if (!first) return { status: "fail", detail: "no encrypted file from " + a.id };
          const r = await b.run({ cmd: "encrypt", input: changed, key: { password: PASSWORD }, opts: { previous: first } });
          if (r.kind !== "OK") return { status: "fail", ms: r.ms, detail: "re-encrypt failed with " + r.kind + ": " + tail(r.stderr) };
          const l1 = first.toString("latin1").split("\n");
          const l2 = r.output.toString("latin1").split("\n");
          if (l1.length !== l2.length) return { status: "fail", detail: "line count changed: " + l1.length + " → " + l2.length };
          const differing = l1.map((l, i) => (l === l2[i] ? -1 : i)).filter((i) => i >= 0);
          const want = changedLine + 2; // header line + one slot line
          if (differing.length !== 1 || differing[0] !== want) {
            return { status: "fail", expected: "only line " + (want + 1) + " differs", actual: "differing lines: " + (differing.map((i) => i + 1).join(", ") || "none"), detail: "diff is not limited to the changed line" };
          }
          const back = compareOutput(await a.run({ cmd: "decrypt", input: r.output, key: { password: PASSWORD } }), changed);
          back.ms = r.ms;
          return back;
        },
      });
    }
  }
  return checks;
}

export function negativeChecks(all: Participant[]): Check[] {
  const checks: Check[] = [];
  const linesVec = vectorFile("lines-default", "encrypted.txt");
  const linesText = linesVec.toString("latin1").split("\n");
  const pw = { password: "hunter2" };

  const tampered = linesText.slice();
  tampered[2] = (tampered[2][0] === "A" ? "B" : "A") + tampered[2].slice(1);
  const badToken = linesText.slice();
  badToken[2] = "!!!not-base64!!!";

  const blob = vectorFile("blob-partial-chunk", "encrypted.txt").toString("latin1").split("\n");
  const blobHead = blob.slice(0, 2);
  const records = Buffer.from(blob.slice(2).join(""), "base64url");
  const rebuild = (raw: Buffer): Buffer => {
    const b64 = raw.toString("base64url");
    const lines: string[] = [];
    for (let i = 0; i < b64.length; i += 76) lines.push(b64.slice(i, i + 76));
    return Buffer.from([...blobHead, ...lines, ""].join("\n"), "latin1");
  };
  const truncated = rebuild(records.subarray(0, 3 * 80));
  const swapped = rebuild(Buffer.concat([records.subarray(80, 160), records.subarray(0, 80), records.subarray(160)]));
  const extended = rebuild(Buffer.concat([records, records.subarray(records.length - 24)]));

  const sealed = vectorFile("lines-ws0-pad0-seal", "encrypted.txt").toString("latin1").split("\n");
  const sealedMinusLine = [...sealed.slice(0, 4), ...sealed.slice(5)];
  const sealedSwapped = sealed.slice();
  [sealedSwapped[3], sealedSwapped[4]] = [sealedSwapped[4], sealedSwapped[3]];
  const sshVec = vectorFile("lines-ssh-ed25519", "encrypted.txt");
  const b = (lines: string[]): Buffer => Buffer.from(lines.join("\n"), "latin1");
  const plain = Buffer.from("x\n");

  type N = { name: string; about: string; expect: "AUTH" | "MALFORMED" | "ENV" | "USAGE"; run: (p: Participant) => Promise<OpResult> };
  const tests: N[] = [
    { name: "wrong-password", about: "decrypt with the wrong password", expect: "AUTH", run: (p) => p.run({ cmd: "decrypt", input: linesVec, key: { password: "wrong" } }) },
    { name: "tampered-line", about: "one character of an encrypted line changed", expect: "AUTH", run: (p) => p.run({ cmd: "decrypt", input: b(tampered), key: pw }) },
    { name: "wrong-ssh-key", about: "decrypt an ed25519-keyed file with the rsa key", expect: "AUTH", run: (p) => p.run({ cmd: "decrypt", input: sshVec, key: { ssh: ["test_rsa"] } }) },
    { name: "blob-truncated", about: "last chunk of a blob removed", expect: "AUTH", run: (p) => p.run({ cmd: "decrypt", input: truncated, key: pw }) },
    { name: "blob-chunks-swapped", about: "two chunks of a blob swapped", expect: "AUTH", run: (p) => p.run({ cmd: "decrypt", input: swapped, key: pw }) },
    { name: "blob-extended", about: "a chunk appended to a blob", expect: "AUTH", run: (p) => p.run({ cmd: "decrypt", input: extended, key: pw }) },
    { name: "seal-line-removed", about: "a line removed from a sealed file", expect: "AUTH", run: (p) => p.run({ cmd: "decrypt", input: b(sealedMinusLine), key: pw }) },
    { name: "seal-lines-swapped", about: "two lines swapped in a sealed file", expect: "AUTH", run: (p) => p.run({ cmd: "decrypt", input: b(sealedSwapped), key: pw }) },
    { name: "not-ssenc", about: "input is not an ssenc1 file", expect: "MALFORMED", run: (p) => p.run({ cmd: "decrypt", input: Buffer.from("hello world\n"), key: pw }) },
    { name: "header-out-of-range", about: "pad=99999 in the header", expect: "MALFORMED", run: (p) => p.run({ cmd: "decrypt", input: b(["#ssenc1 lines ws=1 pad=99999", ...linesText.slice(1)]), key: pw }) },
    { name: "no-slots", about: "header without any key slot", expect: "MALFORMED", run: (p) => p.run({ cmd: "decrypt", input: b([linesText[0], ...linesText.slice(2)]), key: pw }) },
    { name: "invalid-token", about: "a body line that is not base64url", expect: "MALFORMED", run: (p) => p.run({ cmd: "decrypt", input: b(badToken), key: pw }) },
    { name: "inspect-garbage", about: "inspect on something that is not ssenc1", expect: "MALFORMED", run: (p) => p.run({ cmd: "inspect", input: Buffer.from("#ssenc2 future\n") }) },
    { name: "ecdsa-key", about: "encrypt with an ECDSA key (signatures are not deterministic)", expect: "ENV", run: (p) => p.run({ cmd: "encrypt", input: plain, key: { ssh: ["test_ecdsa"] }, opts: {} }) },
    { name: "key-not-in-agent", about: "encrypt with an ssh key that is not loaded in the agent", expect: "ENV", run: (p) => p.run({ cmd: "encrypt", input: plain, key: { ssh: ["test_absent"] }, opts: {} }) },
    { name: "no-agent", about: "ssh key but no reachable agent (browser: no signer given)", expect: "ENV", run: (p) => p.run({ cmd: "decrypt", input: sshVec, key: { ssh: ["test_ed25519"] }, noAgent: true }) },
    { name: "empty-password", about: "encrypt with an empty password", expect: "USAGE", run: (p) => p.run({ cmd: "encrypt", input: plain, key: { password: "" }, opts: { kdf: CHEAP_KDF } }) },
    { name: "seal-in-blob-mode", about: "--seal together with blob mode", expect: "USAGE", run: (p) => p.run({ cmd: "encrypt", input: plain, key: pw, opts: { kdf: CHEAP_KDF, mode: "blob", seal: true } }) },
  ];
  for (const p of all) {
    for (const t of tests) {
      checks.push({
        id: "negative." + p.id + "." + t.name, suite: "negative", title: p.id + ": " + t.about + " → " + t.expect,
        consumer: p.id, case: t.name, mode: t.expect, key: t.about,
        run: async () => expectKind(await t.run(p), t.expect),
      });
    }
  }
  return checks;
}

/** inspect must print byte-identical JSON in every implementation. */
export function inspectChecks(all: Participant[]): Check[] {
  const checks: Check[] = [];
  const expected: Record<string, string> = {
    "lines-pad1-multislot": '{"format":"ssenc1","mode":"lines","ws":true,"pad":1,"seal":false,"slots":[{"type":"pw","kdf":"argon2id","m":64,"t":2,"p":4},{"type":"ssh","keyType":"ssh-ed25519","fingerprint":"@ED@"},{"type":"ssh","keyType":"ssh-rsa","fingerprint":"@RSA@"}]}\n',
    "lines-ws0-pad0-seal": '{"format":"ssenc1","mode":"lines","ws":false,"pad":0,"seal":true,"slots":[{"type":"pw","kdf":"argon2id","m":8192,"t":1,"p":1}]}\n',
    "blob-small-chunks": '{"format":"ssenc1","mode":"blob","chunk":64,"slots":[{"type":"pw","kdf":"argon2id","m":8192,"t":1,"p":1}]}\n',
  };
  const fp = (name: string): string => {
    const m = /#slot ssh \S+ (SHA256:\S+)/.exec(vectorFile(name, "encrypted.txt").toString("latin1"));
    return m ? m[1] : "?";
  };
  expected["lines-pad1-multislot"] = expected["lines-pad1-multislot"]
    .replace("@ED@", fp("lines-ssh-ed25519")).replace("@RSA@", fp("blob-ssh-rsa"));
  for (const p of all) {
    for (const [name, want] of Object.entries(expected)) {
      checks.push({
        id: "vectors." + p.id + "." + name + ".inspect", suite: "vectors", title: p.id + " inspects vector " + name,
        consumer: p.id, case: name, mode: "inspect", key: "none",
        run: async () => {
          const r = await p.run({ cmd: "inspect", input: vectorFile(name, "encrypted.txt") });
          if (r.kind !== "OK") return { status: "fail", detail: "inspect failed with " + r.kind + ": " + tail(r.stderr) };
          const got = r.output.toString("utf8");
          return got === want ? { status: "pass", ms: r.ms } : { status: "fail", expected: want.trim(), actual: got.trim(), detail: "inspect output differs" };
        },
      });
    }
  }
  return checks;
}

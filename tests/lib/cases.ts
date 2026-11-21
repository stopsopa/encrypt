// The case list: fixture x mode x key. Every stage and the report derive from this table.
import type { EncryptOpts, KeySpec } from "./common.ts";
import { CHEAP_KDF, PASSWORD } from "./common.ts";
import { FIXTURES } from "./fixtures.ts";

export type ModeName = "lines-ws1" | "lines-ws0" | "blob";
export type KeyName = "password" | "ssh-ed25519" | "ssh-rsa" | "two-slot";

export type Case = {
  id: string;
  fixture: string;
  mode: ModeName;
  key: KeyName;
  encryptKey: KeySpec;
  /** Keys the result must open with; a two-slot case is decrypted once with each. */
  decryptKeys: { label: string; key: KeySpec }[];
  opts: EncryptOpts;
};

export const MODES: Record<ModeName, EncryptOpts> = {
  "lines-ws1": { mode: "lines", ws: true },
  "lines-ws0": { mode: "lines", ws: false },
  blob: { mode: "blob" },
};

const KEYSETS: Record<KeyName, { encrypt: KeySpec; decrypt: { label: string; key: KeySpec }[] }> = {
  password: { encrypt: { password: PASSWORD }, decrypt: [{ label: "password", key: { password: PASSWORD } }] },
  "ssh-ed25519": { encrypt: { ssh: ["test_ed25519"] }, decrypt: [{ label: "ssh-ed25519", key: { ssh: ["test_ed25519"] } }] },
  "ssh-rsa": { encrypt: { ssh: ["test_rsa"] }, decrypt: [{ label: "ssh-rsa", key: { ssh: ["test_rsa"] } }] },
  "two-slot": {
    encrypt: { password: PASSWORD, ssh: ["test_ed25519"] },
    decrypt: [
      { label: "two-slot (password)", key: { password: PASSWORD } },
      { label: "two-slot (ssh-ed25519)", key: { ssh: ["test_ed25519"] } },
    ],
  },
};

/** Fixtures that also run with every ssh key type and with two slots. */
const KEY_VARIETY_FIXTURES = ["text-lf", "whitespace", "binary-nul"];

function make(fixture: string, mode: ModeName, key: KeyName): Case {
  return {
    id: fixture + "." + mode + "." + key, fixture, mode, key,
    encryptKey: KEYSETS[key].encrypt, decryptKeys: KEYSETS[key].decrypt,
    opts: { ...MODES[mode], kdf: CHEAP_KDF },
  };
}

export const CASES: Case[] = [];
for (const f of FIXTURES) {
  // Megabyte-sized random binaries only make sense as blobs (as "lines" they would be
  // thousands of lines of noise and take the Bash implementation minutes).
  const modes: ModeName[] = f.kind === "large-binary" ? ["blob"] : ["lines-ws1", "lines-ws0", "blob"];
  for (const m of modes) CASES.push(make(f.name, m, "password"));
}
for (const f of KEY_VARIETY_FIXTURES) {
  for (const m of ["lines-ws1", "lines-ws0", "blob"] as ModeName[]) {
    for (const k of ["ssh-ed25519", "ssh-rsa", "two-slot"] as KeyName[]) CASES.push(make(f, m, k));
  }
}

export function caseById(id: string): Case {
  const c = CASES.find((x) => x.id === id);
  if (!c) throw new Error("unknown case " + id);
  return c;
}

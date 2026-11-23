#!/usr/bin/env node
// ssenc command line interface (Node.js). See SPEC.md section 7.
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { SsencError, encrypt, decrypt, rekey, inspect, VERSION } from "./ssenc.node.ts";
import type { Key, EncryptOptions } from "./ssenc.node.ts";

const IMPL = import.meta.url.endsWith(".ts") ? "node-ts" : "node-js";

const USAGE = `usage:
  ssenc encrypt [--mode lines|blob|auto] [--no-preserve-ws] [--pad N] [--chunk N] [--kdf PROFILE]
                [--seal] [--previous FILE | --fresh] KEYS [-i IN] [-o OUT]
  ssenc decrypt KEY [-i IN] [-o OUT]
  ssenc rekey   KEY NEWKEYS [--kdf PROFILE] [--rewrap-only] [-i IN] [-o OUT]
  ssenc inspect [-i IN]
  ssenc --version

  KEY/KEYS  --password-file F | env SSENC_PASSWORD | --ssh-key PUBFILE_OR_FINGERPRINT
  NEWKEYS   --new-password-file F | env SSENC_NEW_PASSWORD | --new-ssh-key PUBFILE_OR_FINGERPRINT`;

function usage(msg: string): never {
  throw new SsencError("USAGE", msg + "\n" + USAGE);
}

function readPasswordFile(path: string): Uint8Array {
  let b: Uint8Array;
  try {
    b = readFileSync(path);
  } catch (e) {
    throw new SsencError("USAGE", "cannot read password file " + path + ": " + (e as Error).message);
  }
  if (b.length && b[b.length - 1] === 10) b = b.subarray(0, b.length - 1);
  if (b.length && b[b.length - 1] === 13) b = b.subarray(0, b.length - 1);
  return b;
}

function sshKeyArg(arg: string): Key {
  if (arg.startsWith("SHA256:")) return { type: "ssh", fingerprint: arg };
  let text: string;
  try {
    text = readFileSync(arg, "utf8");
  } catch (e) {
    throw new SsencError("USAGE", "cannot read ssh public key file " + arg + ": " + (e as Error).message);
  }
  return { type: "ssh", publicKey: text };
}

async function promptPassword(label: string): Promise<Uint8Array> {
  const stdin = process.stdin;
  process.stderr.write(label);
  stdin.setRawMode(true);
  stdin.resume();
  const bytes: number[] = [];
  return new Promise<Uint8Array>((resolve, reject) => {
    const onData = (d: Buffer): void => {
      for (const c of d) {
        if (c === 13 || c === 10) {
          stdin.setRawMode(false);
          stdin.pause();
          stdin.off("data", onData);
          process.stderr.write("\n");
          resolve(new Uint8Array(bytes));
          return;
        }
        if (c === 3) {
          stdin.setRawMode(false);
          process.stderr.write("\n");
          reject(new SsencError("USAGE", "interrupted"));
          return;
        }
        if (c === 127 || c === 8) bytes.pop();
        else bytes.push(c);
      }
    };
    stdin.on("data", onData);
  });
}

async function main(argv: string[]): Promise<void> {
  if (argv[0] === "--version") {
    process.stdout.write("ssenc " + IMPL + " " + VERSION + "\n");
    return;
  }
  if (argv.length === 0 || argv[0] === "--help" || argv[0] === "-h") {
    process.stdout.write(USAGE + "\n");
    return;
  }
  const cmd = argv[0];
  if (!["encrypt", "decrypt", "rekey", "inspect"].includes(cmd)) usage("unknown command '" + cmd + "'");
  let inPath: string | undefined, outPath: string | undefined, pwFile: string | undefined, newPwFile: string | undefined;
  let previous: string | undefined, fresh = false, rewrapOnly = false, kdf: string | undefined;
  const sshKeys: string[] = [], newSshKeys: string[] = [];
  const opts: EncryptOptions = {};
  for (let i = 1; i < argv.length; i++) {
    const a = argv[i];
    const value = (): string => {
      if (i + 1 >= argv.length) usage("option " + a + " needs a value");
      return argv[++i];
    };
    const int = (): number => {
      const v = value();
      if (!/^(0|[1-9][0-9]*)$/.test(v)) usage("option " + a + " needs a non-negative integer");
      return Number(v);
    };
    const only = (...cmds: string[]): void => {
      if (!cmds.includes(cmd)) usage("option " + a + " is not valid for '" + cmd + "'");
    };
    switch (a) {
      case "-i": inPath = value(); break;
      case "-o": only("encrypt", "decrypt", "rekey"); outPath = value(); break;
      case "--password-file": only("encrypt", "decrypt", "rekey"); pwFile = value(); break;
      case "--ssh-key": only("encrypt", "decrypt", "rekey"); sshKeys.push(value()); break;
      case "--new-password-file": only("rekey"); newPwFile = value(); break;
      case "--new-ssh-key": only("rekey"); newSshKeys.push(value()); break;
      case "--mode": {
        only("encrypt");
        const v = value();
        if (v !== "lines" && v !== "blob" && v !== "auto") usage("--mode must be lines, blob or auto");
        opts.mode = v;
        break;
      }
      case "--no-preserve-ws": only("encrypt"); opts.preserveWhitespace = false; break;
      case "--pad": only("encrypt"); opts.pad = int(); break;
      case "--chunk": only("encrypt"); opts.chunk = int(); break;
      case "--seal": only("encrypt"); opts.seal = true; break;
      case "--kdf": only("encrypt", "rekey"); kdf = value(); break;
      case "--previous": only("encrypt"); previous = value(); break;
      case "--fresh": only("encrypt"); fresh = true; break;
      case "--rewrap-only": only("rekey"); rewrapOnly = true; break;
      default: usage("unknown option '" + a + "'");
    }
  }
  if (previous !== undefined && fresh) usage("--previous and --fresh exclude each other");

  const readInput = (): Uint8Array => {
    try {
      return readFileSync(inPath === undefined ? 0 : inPath);
    } catch (e) {
      throw new SsencError("USAGE", "cannot read input: " + (e as Error).message);
    }
  };
  const writeOutput = (data: Uint8Array | string): void => {
    if (outPath === undefined) process.stdout.write(data);
    else writeFileSync(outPath, data);
  };

  if (cmd === "inspect") {
    process.stdout.write(JSON.stringify(inspect(readInput())) + "\n");
    return;
  }

  // keys
  const keys: Key[] = [];
  let password: Uint8Array | undefined;
  if (pwFile !== undefined) password = readPasswordFile(pwFile);
  else if (process.env.SSENC_PASSWORD !== undefined) password = new TextEncoder().encode(process.env.SSENC_PASSWORD);
  else if (sshKeys.length === 0) {
    if (!process.stdin.isTTY || inPath === undefined) usage("no key given: use --password-file, SSENC_PASSWORD or --ssh-key");
    password = await promptPassword("ssenc password: ");
  }
  if (password !== undefined && password.length === 0) usage("password must not be empty");
  if (cmd === "encrypt") {
    if (password !== undefined) keys.push({ type: "password", password });
    for (const k of sshKeys) keys.push(sshKeyArg(k));
  } else {
    if (sshKeys.length > 1) usage("'" + cmd + "' takes a single --ssh-key");
    if (sshKeys.length === 1) keys.push(sshKeyArg(sshKeys[0]));
    else keys.push({ type: "password", password: password as Uint8Array });
  }

  if (cmd === "encrypt") {
    if (kdf !== undefined) opts.kdf = kdf;
    if (previous !== undefined) {
      try {
        opts.previous = readFileSync(previous);
      } catch (e) {
        throw new SsencError("USAGE", "cannot read --previous file: " + (e as Error).message);
      }
    } else if (!fresh && outPath !== undefined && existsSync(outPath)) {
      const existing = readFileSync(outPath);
      if (existing.subarray(0, 8).toString("latin1") === "#ssenc1 ") opts.previous = existing;
    }
    const input = readInput();
    let out: string;
    try {
      out = await encrypt(input, keys, opts);
    } catch (e) {
      if (e instanceof SsencError && e.kind === "AUTH" && opts.previous !== undefined && previous === undefined) {
        throw new SsencError("AUTH", "the existing output file cannot be opened with this key; use --fresh to overwrite it with a new data key");
      }
      throw e;
    }
    writeOutput(out);
  } else if (cmd === "decrypt") {
    writeOutput(await decrypt(readInput(), keys[0]));
  } else {
    const newKeys: Key[] = [];
    let newPassword: Uint8Array | undefined;
    if (newPwFile !== undefined) newPassword = readPasswordFile(newPwFile);
    else if (process.env.SSENC_NEW_PASSWORD !== undefined) newPassword = new TextEncoder().encode(process.env.SSENC_NEW_PASSWORD);
    if (newPassword !== undefined) {
      if (newPassword.length === 0) usage("new password must not be empty");
      newKeys.push({ type: "password", password: newPassword });
    }
    for (const k of newSshKeys) newKeys.push(sshKeyArg(k));
    if (newKeys.length === 0) usage("no new key given: use --new-password-file, SSENC_NEW_PASSWORD or --new-ssh-key");
    writeOutput(await rekey(readInput(), keys[0], newKeys, { rotateDataKey: !rewrapOnly, kdf }));
  }
}

const EXIT: Record<string, number> = { USAGE: 1, AUTH: 2, MALFORMED: 3, ENV: 4 };

main(process.argv.slice(2)).then(
  () => {
    process.exitCode = 0;
  },
  (e: unknown) => {
    if (e instanceof SsencError) {
      process.stderr.write("ssenc: " + e.kind + ": " + e.message + "\n");
      process.exitCode = EXIT[e.kind];
    } else {
      process.stderr.write("ssenc: internal error: " + (e instanceof Error ? e.stack : String(e)) + "\n");
      process.exitCode = 70;
    }
  },
);

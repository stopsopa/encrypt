// The five participants of the cross tests, behind one interface.
import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { cpus, tmpdir } from "node:os";
import { join } from "node:path";
import type { ErrorKind, KeySpec, Op, OpResult, Participant, ResultKind } from "./common.ts";
import { KEYS, ROOT, TESTS, limiter } from "./common.ts";
import { agentSign } from "./agent-sign.ts";

const EXIT_KIND: Record<number, ErrorKind> = { 1: "USAGE", 2: "AUTH", 3: "MALFORMED", 4: "ENV" };

/** All server-side CLI processes share one limit so the machine is not oversubscribed. */
const serverLimit = limiter(Math.max(2, Math.min(8, cpus().length)));

function exec(cmd: string, args: string[], env: NodeJS.ProcessEnv): Promise<{ code: number; stdout: Buffer; stderr: string; ms: number }> {
  return new Promise((resolve) => {
    const t0 = performance.now();
    const child = spawn(cmd, args, { env, stdio: ["ignore", "pipe", "pipe"] });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    child.stdout.on("data", (d: Buffer) => out.push(d));
    child.stderr.on("data", (d: Buffer) => err.push(d));
    child.on("error", (e) => resolve({ code: 127, stdout: Buffer.alloc(0), stderr: String(e), ms: performance.now() - t0 }));
    child.on("close", (code, signal) => resolve({
      code: code ?? 128, stdout: Buffer.concat(out),
      stderr: Buffer.concat(err).toString() + (signal ? "\nkilled by " + signal : ""), ms: performance.now() - t0,
    }));
  });
}

class CliParticipant implements Participant {
  id: string;
  what: string;
  where = "server" as const;
  how = "CLI";
  private bin: string;
  private env: Record<string, string>;

  constructor(id: string, what: string, bin: string, env: Record<string, string> = {}) {
    this.id = id;
    this.what = what;
    this.bin = join(ROOT, bin);
    this.env = env;
  }

  async version(): Promise<string> {
    if (!existsSync(this.bin)) return "MISSING: " + this.bin;
    const r = await exec(this.bin, ["--version"], { ...process.env, ...this.env });
    return r.code === 0 ? r.stdout.toString().trim() : "BROKEN: " + r.stderr.trim();
  }

  raw(args: string[]): Promise<OpResult> {
    return serverLimit(async () => {
      const env: NodeJS.ProcessEnv = { ...process.env, ...this.env };
      delete env.SSENC_PASSWORD;
      delete env.SSENC_NEW_PASSWORD;
      delete env.NODE_OPTIONS;
      const r = await exec(this.bin, args, env);
      const kind: ResultKind = r.code === 0 ? "OK" : EXIT_KIND[r.code] ?? "CRASH";
      return { kind, output: r.stdout, stderr: r.stderr, ms: r.ms };
    });
  }

  run(op: Op): Promise<OpResult> {
    return serverLimit(async () => {
      const dir = mkdtempSync(join(tmpdir(), "ssenc-op-"));
      try {
        const args: string[] = [op.cmd, "-i", join(dir, "in")];
        writeFileSync(join(dir, "in"), op.input);
        const env: NodeJS.ProcessEnv = { ...process.env, ...this.env };
        delete env.SSENC_PASSWORD;
        delete env.SSENC_NEW_PASSWORD;
        delete env.NODE_OPTIONS;
        const keyArgs = (spec: KeySpec, prefix: string, file: string): void => {
          if (spec.password !== undefined) {
            writeFileSync(join(dir, file), spec.password + "\n");
            args.push("--" + prefix + "password-file", join(dir, file));
          }
          for (const k of spec.ssh ?? []) args.push("--" + prefix + "ssh-key", join(KEYS, k + ".pub"));
        };
        if (op.cmd !== "inspect") {
          args.push("-o", join(dir, "out"));
          keyArgs(op.key, "", "pw");
          if ("noAgent" in op && op.noAgent) env.SSH_AUTH_SOCK = join(dir, "no-such-agent");
        }
        if (op.cmd === "encrypt") {
          const o = op.opts;
          if (o.mode) args.push("--mode", o.mode);
          if (o.ws === false) args.push("--no-preserve-ws");
          if (o.pad !== undefined) args.push("--pad", String(o.pad));
          if (o.chunk !== undefined) args.push("--chunk", String(o.chunk));
          if (o.kdf) args.push("--kdf", o.kdf);
          if (o.seal) args.push("--seal");
          if (o.previous) {
            writeFileSync(join(dir, "prev"), o.previous);
            args.push("--previous", join(dir, "prev"));
          }
        } else if (op.cmd === "rekey") {
          keyArgs(op.newKey, "new-", "newpw");
          if (op.kdf) args.push("--kdf", op.kdf);
          if (op.rewrapOnly) args.push("--rewrap-only");
        }
        const r = await exec(this.bin, args, env);
        let kind: ResultKind = r.code === 0 ? "OK" : EXIT_KIND[r.code] ?? "CRASH";
        let output: Buffer = Buffer.alloc(0);
        if (kind === "OK") {
          if (op.cmd === "inspect") output = r.stdout;
          else if (existsSync(join(dir, "out"))) output = readFileSync(join(dir, "out"));
          else kind = "CRASH";
        }
        const why = r.code === 130 || r.code === 143 ? " (the process was interrupted: SIGINT/SIGTERM, e.g. Ctrl+C)" : "";
        const stderr = kind === "CRASH" ? "unexpected exit code " + r.code + why + (r.stderr ? ": " + r.stderr : ", nothing on stderr") : r.stderr;
        return { kind, output, stderr, ms: r.ms };
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    });
  }

  async close(): Promise<void> {}
}

/** dist/ssenc.browser.js in headless Chromium, driven through Playwright. */
class BrowserParticipant implements Participant {
  id = "browser-js";
  what = "typescript/dist/ssenc.browser.js (transpiled)";
  where = "browser" as const;
  how = "Playwright";
  browserVersion = "";
  private one = limiter(1);
  private page: import("playwright").Page | null = null;
  private browser: import("playwright").Browser | null = null;
  private server: import("node:http").Server | null = null;
  private pubKeys: Record<string, string> = {};

  async start(): Promise<void> {
    const { chromium } = await import("playwright");
    const files: Record<string, [string, string]> = {
      "/": [join(TESTS, "browser", "harness.html"), "text/html; charset=utf-8"],
      "/ssenc.browser.js": [join(ROOT, "typescript", "dist", "ssenc.browser.js"), "text/javascript; charset=utf-8"],
    };
    this.server = createServer((req, res) => {
      const f = files[req.url ?? ""];
      if (!f) {
        res.writeHead(404).end("not found");
        return;
      }
      res.writeHead(200, { "content-type": f[1], "cache-control": "no-store" }).end(readFileSync(f[0]));
    });
    await new Promise<void>((r) => this.server!.listen(0, "127.0.0.1", r));
    const port = (this.server.address() as AddressInfo).port;
    this.browser = await chromium.launch();
    this.browserVersion = "Chromium " + this.browser.version();
    this.page = await this.browser.newPage();
    this.page.on("pageerror", (e) => console.error("browser page error:", e));
    await this.page.exposeFunction("sshSign", async (blobB64: string, dataB64: string): Promise<string> =>
      (await agentSign(Buffer.from(blobB64, "base64"), Buffer.from(dataB64, "base64"))).toString("base64"));
    await this.page.goto("http://127.0.0.1:" + port + "/");
    await this.page.waitForFunction("window.ssencReady === true", undefined, { timeout: 30000 });
    for (const k of ["test_ed25519", "test_rsa", "test_ecdsa", "test_absent"]) {
      this.pubKeys[k] = readFileSync(join(KEYS, k + ".pub"), "utf8");
    }
  }

  async version(): Promise<string> {
    return "ssenc " + (await this.page!.evaluate("window.ssencBuild")) + " in " + this.browserVersion;
  }

  run(op: Op): Promise<OpResult> {
    return this.one(async () => {
      const wire: Record<string, unknown> = { ...op, input: op.input.toString("base64"), pubKeys: this.pubKeys };
      if (op.cmd === "encrypt") {
        wire.opts = { ...op.opts, previous: op.opts.previous?.toString("base64") };
      }
      try {
        const r = await this.page!.evaluate((o) => (window as unknown as { runOp: (o: unknown) => Promise<{ kind: ResultKind; output: string; stderr: string; ms: number }> }).runOp(o), wire);
        return { kind: r.kind, output: Buffer.from(r.output, "base64"), stderr: r.stderr, ms: r.ms };
      } catch (e) {
        return { kind: "CRASH", output: Buffer.alloc(0), stderr: "playwright: " + String(e), ms: 0 };
      }
    });
  }

  async close(): Promise<void> {
    await this.browser?.close();
    await new Promise<void>((r) => (this.server ? this.server.close(() => r()) : r()));
  }
}

export type Participants = { all: Participant[]; server: Participant[]; browser: Participant[]; versions: Record<string, string> };

export async function startParticipants(only?: string[]): Promise<Participants> {
  const cli = [
    new CliParticipant("rust", "rust/target/release/ssenc", "rust/bin/ssenc"),
    new CliParticipant("bash", "bash/bin/ssenc (bash + openssl + ssh-keygen)", "bash/bin/ssenc"),
    new CliParticipant("node-ts", "typescript/dist/ssenc.node.ts, run by Node with native type stripping", "typescript/bin/ssenc"),
    new CliParticipant("node-js", "typescript/dist/ssenc.node.js (transpiled)", "typescript/bin/ssenc", { SSENC_TS_BUILD: "js" }),
  ].filter((p) => !only || only.includes(p.id));
  const versions: Record<string, string> = {};
  for (const p of cli) versions[p.id] = await p.version();
  const browser: BrowserParticipant[] = [];
  if (!only || only.includes("browser-js")) {
    const b = new BrowserParticipant();
    await b.start();
    versions[b.id] = await b.version();
    browser.push(b);
  }
  return { all: [...cli, ...browser], server: cli, browser, versions };
}

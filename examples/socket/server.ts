/**
 * Encoder process: stays running, listens on a unix socket and encrypts / decrypts the files
 * named in the requests it receives, with one ssh key held by ssh-agent.
 *
 * Why: the ssenc command starts a new process for every file. This process is started once,
 * so a file costs only the work itself: one signature made by ssh-agent plus the encryption
 * (a few milliseconds). Nothing about the encryption is weakened and nothing is cached: every
 * file still gets its own data key and its own signature. The files are ordinary ssenc
 * files, readable by the ssenc command of every implementation.
 *
 * Usage (from the repository root; the protocol is described in examples/socket/protocol.ts):
 *
 *   node examples/socket/server.ts --ssh-key examples/socket/tmp/key.pub --seal
 *   node examples/socket/server.ts --ssh-key SHA256:… --mode auto --socket /some/where/ssenc.sock
 *   node examples/socket/server.ts --help
 *
 *   --ssh-key FILE.pub|SHA256:…   required; the private key must be loaded in the agent that
 *                                 SSH_AUTH_SOCK points to
 *   --seal                        as in "ssenc encrypt": detect removed, added and moved lines
 *   --mode lines|blob|auto        as in "ssenc encrypt"; default lines
 *   --socket PATH                 default: examples/socket/tmp/ssenc.sock
 *
 * "encode" behaves like "ssenc encrypt -i IN -o OUT": when OUT already is an encrypted file
 * it is reused, so only the edited lines change in it. "decode" is "ssenc decrypt".
 *
 * Stop it with Ctrl+C or kill (SIGTERM): the request being handled is finished first.
 *
 * Who can use it: the socket file is created readable and writable only by you (mode 600).
 * Everyone who can connect can decrypt every file this key opens, exactly like everyone who
 * can reach your ssh-agent, so keep the socket in a directory of your own.
 *
 * Run by Node directly (native type stripping, no flags, Node.js >= 22.18).
 */
import { existsSync, mkdirSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { connect, createServer } from "node:net";
import type { Server, Socket } from "node:net";
import { dirname } from "node:path";
import { createInterface } from "node:readline";
import { SsencError, decrypt, encrypt, sshFingerprint, sshParsePublicKey } from "../../typescript/dist/ssenc.node.ts";
import type { EncryptOptions, Key } from "../../typescript/dist/ssenc.node.ts";
import { DEFAULT_SOCKET, formatError, formatOk, parseRequest, shortSocketPath } from "./protocol.ts";

const th = (msg: string) => new Error(`examples/socket/server.ts error: ${msg}`);

export type ServerOptions = {
  /** Path of a .pub file, or the fingerprint (SHA256:…) of a key loaded in ssh-agent. */
  sshKey: string;
  seal?: boolean;
  mode?: "lines" | "blob" | "auto";
  /** Path of the unix socket to listen on. Default: DEFAULT_SOCKET. */
  socket?: string;
  /** Called with one line per handled request. Default: nothing is logged. */
  log?: (line: string) => void;
};

/** A file that cannot be read or written is a USAGE error, as in the ssenc command. */
function file<T>(what: string, path: string, work: () => T): T {
  try {
    return work();
  } catch (e) {
    throw new SsencError("USAGE", `cannot ${what} ${path}: ${(e as Error).message}`);
  }
}

async function handle(line: string, key: Key, options: EncryptOptions): Promise<string> {
  const started = performance.now();
  try {
    let request;
    try {
      request = parseRequest(line);
    } catch (e) {
      throw new SsencError("USAGE", (e as Error).message);
    }
    const { command, input: inPath, output: outPath } = request;
    const input = file("read input", inPath, () => readFileSync(inPath));
    let output: Uint8Array | string;
    if (command === "encode") {
      // Like the command: an existing encrypted output file is reused, so that only edited lines change.
      let previous: Uint8Array | undefined;
      if (existsSync(outPath)) {
        const existing = file("read existing output file", outPath, () => readFileSync(outPath));
        if (existing.subarray(0, 8).toString("latin1") === "#ssenc1 ") previous = existing;
      }
      output = await encrypt(input, key, previous ? { ...options, previous } : options);
    } else {
      output = await decrypt(input, key);
    }
    file("write output", outPath, () => writeFileSync(outPath, output));
    return formatOk(request, performance.now() - started);
  } catch (e) {
    if (e instanceof SsencError) return formatError(e.kind, e.message);
    return formatError("USAGE", (e as Error).message);
  }
}

function listen(server: Server, path: string): Promise<void> {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    // The socket file is created by listen(): with this umask only its owner can connect.
    const umask = process.umask(0o077);
    server.listen(path, () => {
      process.umask(umask);
      server.off("error", reject);
      resolve();
    });
  });
}

function somebodyListens(path: string): Promise<boolean> {
  return new Promise((resolve) => {
    const probe = connect(path);
    probe.once("connect", () => {
      probe.destroy();
      resolve(true);
    });
    probe.once("error", () => resolve(false));
  });
}

export type RunningServer = {
  /** The path it listens on. */
  socket: string;
  /** No new connections, open ones are dropped; the request being handled still finishes. */
  stop: () => void;
};

/**
 * Starts the encoder process. Resolves when it listens; rejects when the key cannot be used
 * or the socket cannot be created.
 */
export async function startServer(options: ServerOptions): Promise<RunningServer> {
  const log = options.log ?? (() => {});
  const socketPath = shortSocketPath(options.socket ?? DEFAULT_SOCKET);

  let key: Key;
  if (options.sshKey.startsWith("SHA256:")) {
    key = { type: "ssh", fingerprint: options.sshKey };
  } else {
    let text: string;
    try {
      text = readFileSync(options.sshKey, "utf8");
    } catch (e) {
      throw th(`cannot read ssh public key file >${options.sshKey}<: ${(e as Error).message}`);
    }
    key = { type: "ssh", publicKey: text };
    log(`key ${await sshFingerprint(sshParsePublicKey(text))}`);
  }
  // Fail now, not on the first request, when the agent is not reachable or the key is not loaded.
  try {
    await encrypt("", key);
  } catch (e) {
    throw th(`the ssh key >${options.sshKey}< cannot be used: ${(e as Error).message}`);
  }

  const encryptOptions: EncryptOptions = {};
  if (options.seal) encryptOptions.seal = true;
  if (options.mode) encryptOptions.mode = options.mode;

  const sockets = new Set<Socket>();
  let stopping = false;
  // allowHalfOpen: a client may send all its requests, close its side and then read the replies.
  const server = createServer({ allowHalfOpen: true }, (socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
    socket.on("error", () => socket.destroy());
    // One request after another per connection, so the replies come in the order of the requests.
    let queue = Promise.resolve();
    const lines = createInterface({ input: socket });
    lines.on("line", (line) => {
      if (line.trim() === "") return;
      queue = queue.then(async () => {
        if (stopping) return;
        const reply = await handle(line, key, encryptOptions);
        log(`${line.trim()}  =>  ${reply}`);
        if (!socket.destroyed) socket.write(reply + "\n");
      });
    });
    lines.on("close", () => queue.then(() => socket.end()));
  });

  mkdirSync(dirname(socketPath), { recursive: true });
  try {
    await listen(server, socketPath);
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== "EADDRINUSE") {
      throw th(`cannot listen on >${socketPath}<: ${(e as Error).message}`);
    }
    if (await somebodyListens(socketPath)) {
      throw th(`another server already listens on >${socketPath}<`);
    }
    unlinkSync(socketPath); // left behind by a server that was killed
    await listen(server, socketPath);
  }
  log(`listening on ${socketPath}`);
  return {
    socket: socketPath,
    stop: () => {
      stopping = true;
      server.close(); // also removes the socket file
      sockets.forEach((socket) => socket.destroy());
    },
  };
}

const HELP = `Encoder process: encrypts and decrypts files named in requests received on a unix socket.

usage:
  node examples/socket/server.ts --ssh-key FILE.pub|SHA256:… [--seal] [--mode lines|blob|auto] [--socket PATH]

  --ssh-key   required; the private key must be loaded in the agent of SSH_AUTH_SOCK
  --seal      detect removed, added and moved lines (lines mode)
  --mode      default: lines
  --socket    default: ${shortSocketPath(DEFAULT_SOCKET)}

requests, one per line (send them with examples/socket/client.ts):
  encode "<plain file>" "<encrypted file>"
  decode "<encrypted file>" "<plain file>"`;

export async function cli(argv: string[]): Promise<void> {
  const options: ServerOptions = { sshKey: "", log: (line) => console.log(line) };
  for (let i = 0; i < argv.length; i++) {
    const option = argv[i];
    const value = () => {
      if (i + 1 >= argv.length) throw th(`option ${option} needs a value`);
      return argv[++i];
    };
    if (option === "--ssh-key") options.sshKey = value();
    else if (option === "--socket") options.socket = value();
    else if (option === "--seal") options.seal = true;
    else if (option === "--mode") {
      const mode = value();
      if (mode !== "lines" && mode !== "blob" && mode !== "auto") {
        throw th(`--mode must be lines, blob or auto, got >${mode}<`);
      }
      options.mode = mode;
    } else throw th(`unknown option >${option}<, see --help`);
  }
  if (options.sshKey === "") throw th("--ssh-key is required, see --help");

  const { stop } = await startServer(options);
  process.once("SIGINT", stop);
  process.once("SIGTERM", stop);
}

if (import.meta.main) {
  const argv = process.argv.slice(2);
  if (argv.length === 0 || argv.includes("--help") || argv.includes("-h")) {
    console.log(HELP);
    process.exit(1);
  }
  cli(argv).catch((e) => {
    console.error((e as Error).message);
    process.exit(1);
  });
}

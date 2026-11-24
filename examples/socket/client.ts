/**
 * Sends requests to the encoder process (examples/socket/server.ts) and prints its replies.
 * The protocol is described in examples/socket/protocol.ts.
 *
 * Usage (from the repository root, the server has to be running):
 *
 *   # one request from the arguments: command, input file, output file
 *   node examples/socket/client.ts encode source/raw_file.txt target/raw_file.txt.encoded
 *   node examples/socket/client.ts decode target/file.txt.encoded 'source/"file.txt'
 *
 *   # many requests, one per line on standard input, written as in the protocol
 *   printf '%s\n' 'encode "a.txt" "a.txt.enc"' 'encode "b.txt" "b.txt.enc"' | node examples/socket/client.ts
 *
 *   --socket PATH   where the server listens; default: examples/socket/tmp/ssenc.sock
 *   --help
 *
 * - A relative path is relative to the directory the server was started in, not to the
 *   directory of the client. Start both in the same directory or use absolute paths.
 * - Prints one reply line per request. Exit code 0 when every reply is "ok", otherwise 1.
 * - When the server was started a moment ago and does not listen yet, the client waits for
 *   it for up to 3 seconds.
 *
 * Run by Node directly (native type stripping, no flags, Node.js >= 22.18).
 */
import { connect } from "node:net";
import { setTimeout as sleep } from "node:timers/promises";
import { DEFAULT_SOCKET, formatRequest, isOk, shortSocketPath } from "./protocol.ts";

const th = (msg: string) => new Error(`examples/socket/client.ts error: ${msg}`);

function exchange(socketPath: string, lines: string[]): Promise<string[]> {
  return new Promise((done, fail) => {
    const socket = connect(socketPath);
    let received = "";
    socket.setEncoding("utf8");
    socket.on("connect", () => socket.end(lines.map((line) => line + "\n").join("")));
    socket.on("data", (text: string) => (received += text));
    socket.on("error", fail);
    socket.on("close", () => done(received.split("\n").filter((line) => line !== "")));
  });
}

/**
 * Sends the request lines over one connection and returns the reply lines, one per request
 * and in the same order.
 */
export async function send(lines: string[], socket: string = DEFAULT_SOCKET): Promise<string[]> {
  const socketPath = shortSocketPath(socket);
  const giveUp = Date.now() + 3000;
  let replies: string[];
  for (;;) {
    try {
      replies = await exchange(socketPath, lines);
      break;
    } catch (e) {
      const code = (e as NodeJS.ErrnoException).code;
      const notYet = code === "ENOENT" || code === "ECONNREFUSED";
      if (!notYet || Date.now() > giveUp) {
        throw th(`cannot reach the server on >${socketPath}<: ${(e as Error).message}`);
      }
      await sleep(50);
    }
  }
  if (replies.length !== lines.length) {
    throw th(`sent ${lines.length} requests but received ${replies.length} replies; was the server stopped?`);
  }
  return replies;
}

const HELP = `Sends requests to the encoder process (examples/socket/server.ts) and prints its replies.

usage:
  node examples/socket/client.ts [--socket PATH] encode <plain file> <encrypted file>
  node examples/socket/client.ts [--socket PATH] decode <encrypted file> <plain file>
  node examples/socket/client.ts [--socket PATH] < requests.txt

  --socket    default: ${shortSocketPath(DEFAULT_SOCKET)}

requests.txt has one request per line:
  encode "<plain file>" "<encrypted file>"
  decode "<encrypted file>" "<plain file>"

exit code: 0 when every reply is "ok", otherwise 1`;

async function readStdin(): Promise<string> {
  let text = "";
  process.stdin.setEncoding("utf8");
  for await (const part of process.stdin) text += part;
  return text;
}

/** Returns the exit code. */
export async function cli(argv: string[]): Promise<number> {
  const args = [...argv];
  let socket: string | undefined;
  const at = args.indexOf("--socket");
  if (at !== -1) {
    if (at + 1 >= args.length) throw th("option --socket needs a value");
    socket = args[at + 1];
    args.splice(at, 2);
  }

  let lines: string[];
  if (args.length === 0) {
    lines = (await readStdin()).split("\n").filter((line) => line.trim() !== "");
    if (lines.length === 0) throw th("no requests on standard input, see --help");
  } else {
    const [command, input, output] = args;
    if (args.length !== 3 || (command !== "encode" && command !== "decode")) {
      throw th(`expected: encode|decode <input file> <output file>, got >${args.join(" ")}<, see --help`);
    }
    lines = [formatRequest({ command, input, output })];
  }

  const replies = await send(lines, socket);
  for (const reply of replies) console.log(reply);
  return replies.every(isOk) ? 0 : 1;
}

if (import.meta.main) {
  const argv = process.argv.slice(2);
  const request = argv.filter((arg, i) => arg !== "--socket" && argv[i - 1] !== "--socket");
  // Nothing in the arguments and nothing piped in: there is nothing to send.
  if (argv.includes("--help") || argv.includes("-h") || (request.length === 0 && process.stdin.isTTY)) {
    console.log(HELP);
    process.exit(1);
  }
  cli(argv).then(
    (code) => process.exit(code),
    (e) => {
      console.error((e as Error).message);
      process.exit(1);
    },
  );
}

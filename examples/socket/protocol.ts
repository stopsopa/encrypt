/**
 * The text protocol between examples/socket/client.ts and examples/socket/server.ts,
 * and the default location of the socket. No logic besides parsing and formatting.
 *
 * One request per line (UTF-8, ends with LF), one reply line per request, in the same order:
 *
 *   encode "source/raw_file.txt" "target/raw_file.txt.encoded"      plain file  -> encrypted file
 *   decode "target/file.txt.encoded" "source/\"file.txt"            encrypted file -> plain file
 *
 *   ok encode "target/raw_file.txt.encoded" 3ms
 *   error AUTH no key slot could be opened with the given key
 *
 * - The first path is always the input, the second the output.
 * - A path is written like a JSON string: in double quotes, with \" for a double quote and
 *   \\ for a backslash. So any file name can be sent, also one with spaces or quotes.
 * - A relative path is relative to the directory the server was started in.
 * - The word after "error" is the kind of the error, the same four as the exit codes of the
 *   ssenc command: USAGE, AUTH, MALFORMED, ENV. The rest of the line is the message.
 *
 * Usage (from any module in this directory):
 *
 *   import { parseRequest, formatRequest, DEFAULT_SOCKET } from "./protocol.ts";
 *
 *   formatRequest({ command: "encode", input: "a.txt", output: "a.txt.enc" });   // 'encode "a.txt" "a.txt.enc"'
 *   parseRequest('decode "a.txt.enc" "a.txt"');   // { command: "decode", input: "a.txt.enc", output: "a.txt" }
 *
 * Run by Node directly (native type stripping, no flags, Node.js >= 22.18).
 */
import { join, relative } from "node:path";

const th = (msg: string) => new Error(`examples/socket/protocol.ts error: ${msg}`);

export type Command = "encode" | "decode";

export type Request = { command: Command; input: string; output: string };

/** Where server and client meet when --socket is not given: tmp/ssenc.sock next to this file. */
export const DEFAULT_SOCKET = join(import.meta.dirname, "tmp", "ssenc.sock");

/**
 * The path of a unix socket is limited to about 100 bytes, so use the path relative to the
 * current directory when that is the shorter one.
 */
export function shortSocketPath(path: string): string {
  const fromHere = relative(process.cwd(), path);
  return fromHere !== "" && fromHere.length < path.length ? fromHere : path;
}

const QUOTED = String.raw`"(?:[^"\\]|\\.)*"`;
const REQUEST = new RegExp(String.raw`^\s*(encode|decode)\s+(${QUOTED})\s+(${QUOTED})\s*$`);

export function parseRequest(line: string): Request {
  const found = REQUEST.exec(line);
  if (!found) {
    throw th(`not a request, expected: encode|decode "<input file>" "<output file>", got >${line}<`);
  }
  const paths = [found[2], found[3]].map((quoted) => {
    try {
      return JSON.parse(quoted) as string;
    } catch {
      throw th(`path is not a valid quoted string >${quoted}<`);
    }
  });
  if (paths.includes("")) throw th(`a path is empty in >${line}<`);
  return { command: found[1] as Command, input: paths[0], output: paths[1] };
}

export function formatRequest(request: Request): string {
  return `${request.command} ${JSON.stringify(request.input)} ${JSON.stringify(request.output)}`;
}

export function formatOk(request: Request, milliseconds: number): string {
  return `ok ${request.command} ${JSON.stringify(request.output)} ${Math.round(milliseconds)}ms`;
}

export function formatError(kind: string, message: string): string {
  return `error ${kind} ${message.replace(/\s*[\r\n]+\s*/g, " ")}`;
}

export function isOk(reply: string): boolean {
  return reply.startsWith("ok ");
}

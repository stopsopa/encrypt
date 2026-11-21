import type { Bytes } from "./01-util.ts";
import { SsencError, concatBytes, sshString, u32be } from "./01-util.ts";
import { sshFingerprint, sshKeyType } from "./06-ssh.ts";

// ---------------------------------------------------------------------------------------
// ssh-agent client (Node.js build). node:net is loaded lazily, only when an ssh key is used.
// ---------------------------------------------------------------------------------------

function agentSocketPath(explicit: string | undefined): string {
  if (explicit) return explicit;
  const env = process.env.SSH_AUTH_SOCK;
  if (env) return env;
  if (process.platform === "win32") return "\\\\.\\pipe\\openssh-ssh-agent";
  throw new SsencError("ENV", "ssh-agent not available: SSH_AUTH_SOCK is not set");
}

async function agentRequest(socketPath: string | undefined, body: Uint8Array): Promise<Bytes> {
  const path = agentSocketPath(socketPath);
  const net = await import("node:net");
  return new Promise<Bytes>((resolve, reject) => {
    const sock = net.connect(path);
    const chunks: Uint8Array[] = [];
    let have = 0;
    let done = false;
    const fail = (why: string): void => {
      if (done) return;
      done = true;
      sock.destroy();
      reject(new SsencError("ENV", "ssh-agent at " + path + ": " + why));
    };
    sock.on("error", (e: Error) => fail(e.message));
    sock.on("close", () => fail("connection closed before a full reply"));
    sock.on("data", (d: Uint8Array) => {
      chunks.push(d);
      have += d.length;
      if (have < 4) return;
      const all = concatBytes(...chunks);
      const len = ((all[0] << 24) | (all[1] << 16) | (all[2] << 8) | all[3]) >>> 0;
      if (len > 1048576) return fail("oversized reply");
      if (all.length >= 4 + len) {
        done = true;
        sock.destroy();
        resolve(all.slice(4, 4 + len));
      }
    });
    sock.write(concatBytes(u32be(body.length), body));
  });
}

function agentReadString(b: Uint8Array, off: number): { value: Uint8Array; next: number } {
  if (off + 4 > b.length) throw new SsencError("ENV", "ssh-agent sent a truncated reply");
  const len = ((b[off] << 24) | (b[off + 1] << 16) | (b[off + 2] << 8) | b[off + 3]) >>> 0;
  if (off + 4 + len > b.length) throw new SsencError("ENV", "ssh-agent sent a truncated reply");
  return { value: b.subarray(off + 4, off + 4 + len), next: off + 4 + len };
}

export async function agentListKeys(socketPath: string | undefined): Promise<Bytes[]> {
  const reply = await agentRequest(socketPath, new Uint8Array([11]));
  if (reply[0] !== 12 || reply.length < 5) throw new SsencError("ENV", "ssh-agent refused to list keys");
  const count = ((reply[1] << 24) | (reply[2] << 16) | (reply[3] << 8) | reply[4]) >>> 0;
  const keys: Bytes[] = [];
  let off = 5;
  for (let i = 0; i < count; i++) {
    const blob = agentReadString(reply, off);
    const comment = agentReadString(reply, blob.next);
    keys.push(blob.value.slice());
    off = comment.next;
  }
  return keys;
}

export async function agentSign(socketPath: string | undefined, blob: Uint8Array, data: Uint8Array): Promise<Bytes> {
  const flags = sshKeyType(blob) === "ssh-rsa" ? 4 : 0;
  const reply = await agentRequest(socketPath,
    concatBytes(new Uint8Array([13]), sshString(blob), sshString(data), u32be(flags)));
  if (reply[0] !== 14) {
    throw new SsencError("ENV", "ssh-agent could not sign with key " + (await sshFingerprint(blob)) +
      " (is it loaded? check: ssh-add -l)");
  }
  return agentReadString(reply, 1).value.slice();
}

export async function agentFindKey(socketPath: string | undefined, fingerprint: string): Promise<Bytes> {
  for (const blob of await agentListKeys(socketPath)) {
    if ((await sshFingerprint(blob)) === fingerprint) return blob;
  }
  throw new SsencError("ENV", "key " + fingerprint + " is not loaded in ssh-agent (check: ssh-add -l)");
}


import type { Bytes } from "./01-util.ts";
import { SsencError } from "./01-util.ts";

// ---------------------------------------------------------------------------------------
// ssh-agent is unreachable from a browser: ssh keys need a caller-supplied `signer`.
// ---------------------------------------------------------------------------------------

const NO_AGENT = "ssh-agent is not reachable from a browser: pass 'publicKey' and a 'signer' function with the ssh key";

export async function agentSign(_socketPath: string | undefined, _blob: Uint8Array, _data: Uint8Array): Promise<Bytes> {
  throw new SsencError("ENV", NO_AGENT);
}

export async function agentFindKey(_socketPath: string | undefined, _fingerprint: string): Promise<Bytes> {
  throw new SsencError("ENV", NO_AGENT);
}


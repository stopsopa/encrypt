import type { Bytes } from "./01-util.ts";
import { SsencError, ascii, b64stdDecode, b64stdEncodeNoPad, concatBytes, sshString, utf8 } from "./01-util.ts";
import { hkdf32, sha256, sha512 } from "./04-prim.ts";

// ---------------------------------------------------------------------------------------
// ssh key handling shared by both builds (SPEC.md section 2.3)
// ---------------------------------------------------------------------------------------

/**
 * Produces the signature blob for `data` with the key `publicKeyBlob`.
 * Must return string(algorithm) || string(signature) exactly as an ssh-agent does; for an
 * ssh-rsa key the algorithm must be rsa-sha2-512.
 */
export type SshSigner = (publicKeyBlob: Uint8Array, data: Uint8Array) => Promise<Uint8Array>;

export const SSH_NAMESPACE = "ssenc-v1@stopsopa";

function sshReadString(b: Uint8Array, off: number): { value: Uint8Array; next: number } | null {
  if (off + 4 > b.length) return null;
  const len = ((b[off] << 24) | (b[off + 1] << 16) | (b[off + 2] << 8) | b[off + 3]) >>> 0;
  if (off + 4 + len > b.length) return null;
  return { value: b.subarray(off + 4, off + 4 + len), next: off + 4 + len };
}

export function sshKeyType(blob: Uint8Array): string {
  const s = sshReadString(blob, 0);
  if (!s) throw new SsencError("ENV", "invalid ssh public key");
  return ascii(s.value);
}

export function sshRequireSupported(keyType: string): void {
  if (keyType !== "ssh-ed25519" && keyType !== "ssh-rsa") {
    throw new SsencError("ENV", "unsupported ssh key type '" + keyType +
      "': only ssh-ed25519 and ssh-rsa give deterministic signatures");
  }
}

/** Parses one line of an OpenSSH public key file ("type base64 [comment]"). */
export function sshParsePublicKey(text: string): Bytes {
  for (const line of text.split(/\r?\n/)) {
    const parts = line.trim().split(/\s+/);
    if (parts.length >= 2 && /^(ssh-|ecdsa-|sk-)/.test(parts[0])) {
      const blob = b64stdDecode(parts[1]);
      if (blob && sshKeyType(blob) === parts[0]) return blob;
    }
  }
  throw new SsencError("ENV", "not an OpenSSH public key");
}

export async function sshFingerprint(blob: Uint8Array): Promise<string> {
  return "SHA256:" + b64stdEncodeNoPad(await sha256(blob));
}

export async function sshSignedData(salt: Uint8Array): Promise<Bytes> {
  const message = concatBytes(utf8("ssenc1 ssh slot"), salt);
  return concatBytes(utf8("SSHSIG"), sshString(utf8(SSH_NAMESPACE)), sshString(new Uint8Array(0)),
    sshString(utf8("sha512")), sshString(await sha512(message)));
}

export async function sshKek(blob: Uint8Array, salt: Uint8Array, signer: SshSigner): Promise<Bytes> {
  const keyType = sshKeyType(blob);
  sshRequireSupported(keyType);
  const data = await sshSignedData(salt);
  let sig: Uint8Array;
  try {
    sig = await signer(blob, data);
  } catch (e) {
    if (e instanceof SsencError) throw e;
    throw new SsencError("ENV", "ssh signer failed: " + (e instanceof Error ? e.message : String(e)));
  }
  const alg = sshReadString(sig, 0);
  const raw = alg ? sshReadString(sig, alg.next) : null;
  const expected = keyType === "ssh-rsa" ? "rsa-sha2-512" : "ssh-ed25519";
  if (!alg || !raw || raw.next !== sig.length || ascii(alg.value) !== expected) {
    throw new SsencError("ENV", "ssh signer returned an unexpected signature (need " + expected + ")");
  }
  return hkdf32(sig, salt, "ssenc1/ssh-kek");
}

import type { Bytes } from "./01-util.ts";
import { SsencError, ascii, b64urlDecode, b64urlEncode } from "./01-util.ts";

// ---------------------------------------------------------------------------------------
// header parsing and serialising (SPEC.md section 2)
// ---------------------------------------------------------------------------------------

export type KdfParams = { m: number; t: number; p: number };

export type PwSlot = { type: "pw"; m: number; t: number; p: number; salt: Bytes; wrapped: Bytes };
export type SshSlot = { type: "ssh"; keyType: string; fingerprint: string; salt: Bytes; wrapped: Bytes };
export type Slot = PwSlot | SshSlot;

export type ParsedFile = {
  mode: "lines" | "blob";
  ws: boolean;
  pad: number;
  chunk: number;
  headerLine: string;
  slots: Slot[];
  slotLines: string[];
  seal: Bytes | null;
  body: Bytes;
};

export function parseKdf(profile: string | KdfParams | undefined): KdfParams {
  let k: KdfParams;
  if (profile === undefined || profile === "default") k = { m: 65536, t: 3, p: 4 };
  else if (profile === "strong") k = { m: 1048576, t: 4, p: 4 };
  else if (typeof profile === "string") {
    const mt = /^m=([1-9][0-9]{0,7}),t=([1-9][0-9]?),p=([1-9][0-9]?)$/.exec(profile);
    if (!mt) throw new SsencError("USAGE", "invalid kdf profile '" + profile + "' (use default, strong or m=..,t=..,p=..)");
    k = { m: Number(mt[1]), t: Number(mt[2]), p: Number(mt[3]) };
  } else k = profile;
  if (!kdfInRange(k)) throw new SsencError("USAGE", "kdf parameters out of range (8*p <= m <= 4194304, 1 <= t <= 64, 1 <= p <= 16)");
  return k;
}

export function kdfInRange(k: KdfParams): boolean {
  return Number.isInteger(k.m) && Number.isInteger(k.t) && Number.isInteger(k.p) &&
    k.p >= 1 && k.p <= 16 && k.t >= 1 && k.t <= 64 && k.m >= 8 * k.p && k.m <= 4194304;
}

export function headerLineFor(mode: "lines" | "blob", ws: boolean, pad: number, chunk: number): string {
  return mode === "lines" ? "#ssenc1 lines ws=" + (ws ? 1 : 0) + " pad=" + pad : "#ssenc1 blob chunk=" + chunk;
}

export function slotLine(s: Slot): string {
  if (s.type === "pw") {
    return "#slot pw argon2id m=" + s.m + ",t=" + s.t + ",p=" + s.p + " " + b64urlEncode(s.salt) + " " + b64urlEncode(s.wrapped);
  }
  return "#slot ssh " + s.keyType + " " + s.fingerprint + " " + b64urlEncode(s.salt) + " " + b64urlEncode(s.wrapped);
}

function decodeField(s: string, len: number, what: string): Bytes {
  const b = b64urlDecode(s);
  if (!b || b.length !== len) throw new SsencError("MALFORMED", "invalid " + what + " in header");
  return b;
}

function parseSlotLine(line: string): Slot {
  let m = /^#slot pw argon2id m=([1-9][0-9]{0,7}),t=([1-9][0-9]?),p=([1-9][0-9]?) ([A-Za-z0-9_-]+) ([A-Za-z0-9_-]+)$/.exec(line);
  if (m) {
    const slot: PwSlot = {
      type: "pw", m: Number(m[1]), t: Number(m[2]), p: Number(m[3]),
      salt: decodeField(m[4], 16, "password slot salt"), wrapped: decodeField(m[5], 48, "wrapped key"),
    };
    if (!kdfInRange(slot)) throw new SsencError("MALFORMED", "argon2id parameters out of range in header");
    return slot;
  }
  m = /^#slot ssh (ssh-ed25519|ssh-rsa) (SHA256:[A-Za-z0-9+\/]{43}) ([A-Za-z0-9_-]+) ([A-Za-z0-9_-]+)$/.exec(line);
  if (m) {
    return {
      type: "ssh", keyType: m[1], fingerprint: m[2],
      salt: decodeField(m[3], 32, "ssh slot salt"), wrapped: decodeField(m[4], 48, "wrapped key"),
    };
  }
  throw new SsencError("MALFORMED", "unrecognised slot line in header");
}

export function parseFile(input: Bytes): ParsedFile {
  let pos = 0;
  const peekLine = (): { text: string; next: number } | null => {
    if (pos >= input.length) return null;
    let end = input.indexOf(10, pos);
    const next = end < 0 ? input.length : end + 1;
    if (end < 0) end = input.length;
    if (end > pos && input[end - 1] === 13) end--;
    if (end - pos > 1024) return { text: ascii(input.subarray(pos, pos + 16)), next };
    return { text: ascii(input.subarray(pos, end)), next };
  };
  const first = peekLine();
  if (!first || !first.text.startsWith("#ssenc1 ")) throw new SsencError("MALFORMED", "not an ssenc1 file (missing '#ssenc1' header)");
  const out: ParsedFile = {
    mode: "lines", ws: true, pad: 0, chunk: 0, headerLine: first.text,
    slots: [], slotLines: [], seal: null, body: input.subarray(0, 0) as Bytes,
  };
  let m = /^#ssenc1 lines ws=([01]) pad=(0|[1-9][0-9]{0,3})$/.exec(first.text);
  if (m) {
    out.ws = m[1] === "1";
    out.pad = Number(m[2]);
    if (out.pad > 4096) throw new SsencError("MALFORMED", "pad out of range in header");
  } else {
    m = /^#ssenc1 blob chunk=([1-9][0-9]{0,6})$/.exec(first.text);
    if (!m) throw new SsencError("MALFORMED", "invalid '#ssenc1' header line");
    out.mode = "blob";
    out.chunk = Number(m[1]);
    if (out.chunk > 1048576) throw new SsencError("MALFORMED", "chunk out of range in header");
  }
  pos = first.next;
  for (;;) {
    const line = peekLine();
    if (!line) break;
    if (line.text.startsWith("#slot ")) {
      if (out.seal) throw new SsencError("MALFORMED", "slot line after seal line");
      out.slots.push(parseSlotLine(line.text));
      out.slotLines.push(line.text);
    } else if (line.text.startsWith("#seal ")) {
      if (out.seal || out.mode !== "lines") throw new SsencError("MALFORMED", "unexpected seal line");
      if (!/^#seal [A-Za-z0-9_-]+$/.test(line.text)) throw new SsencError("MALFORMED", "invalid seal line");
      out.seal = decodeField(line.text.slice(6), 32, "seal");
    } else break;
    pos = line.next;
  }
  if (out.slots.length === 0) throw new SsencError("MALFORMED", "header has no key slots");
  out.body = input.subarray(pos) as Bytes;
  return out;
}

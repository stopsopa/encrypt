// Runs the ssenc library off the main thread, so typing stays smooth while Argon2id works.
// The library is the single-file browser build produced by typescript/compile.sh.
import { encrypt, decryptToString, setKdfCacheSize, SsencError } from "../typescript/dist/ssenc.browser.js";

// The page re-encrypts and decrypts on every change with the same password and the same
// key slot; caching the Argon2id result makes everything after the first run instant.
setKdfCacheSize(8);

async function handle(msg) {
  const key = { type: "password", password: msg.password };
  if (msg.op === "encrypt") {
    if (msg.previous) {
      try {
        // Reusing the previous output keeps its data key, so unchanged lines stay identical.
        return { out: await encrypt(msg.message, key, { previous: msg.previous }) };
      } catch (e) {
        // previous is not ours (other password, or not ssenc1 at all): start fresh
        if (!(e instanceof SsencError) || (e.kind !== "AUTH" && e.kind !== "MALFORMED")) throw e;
      }
    }
    return { out: await encrypt(msg.message, key) };
  }
  if (msg.op === "decrypt") return { text: await decryptToString(msg.encrypted, key) };
  throw new Error("unknown op " + msg.op);
}

self.onmessage = async (event) => {
  const msg = event.data;
  try {
    self.postMessage({ id: msg.id, ok: true, ...(await handle(msg)) });
  } catch (e) {
    self.postMessage({ id: msg.id, ok: false, kind: e instanceof SsencError ? e.kind : "CRASH", message: String(e && e.message ? e.message : e) });
  }
};

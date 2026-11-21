// Encryptor page logic. All cryptography is done by ../typescript/dist/ssenc.browser.js
// (in worker.js); this file only wires the fields together:
//
//   message + key  ->  encrypted output  ->  URL (#enc=...)  ->  sharing link
//                                        ->  decrypted output + rendered markdown
//                                        ->  shell snippets at the bottom
//
// The URL holds only the encrypted text, never the key. Opening such a URL restores the
// encrypted output; as soon as the key is typed (or filled by a password manager)
// everything else follows.

const parent = document.querySelector("#encryptor");
const $ = (sel) => parent.querySelector(sel);
const inputKey = $(".key");
const inputMessage = $(".message");
const inputEncrypted = $(".encrypted");
const inputDecrypted = $(".decrypted");
const zeroMd = $(".decrypted-md");
const status = $(".status");
const copyBtn = $(".copy-btn");
const copyLinkBtn = $(".copy-link-btn");
const sharingLink = $(".sharing-link");
const linkGroup = $(".link-group");
const show = $(".show");

// ---- worker ------------------------------------------------------------------------------
const worker = new Worker(new URL("./worker.js", import.meta.url), { type: "module" });
const pending = new Map();
let nextId = 1;
worker.onmessage = (e) => {
  pending.get(e.data.id)?.(e.data);
  pending.delete(e.data.id);
};
worker.onerror = (e) => setStatus("error", "encryption worker failed to load: " + (e.message || "see console"));
const call = (op, data) => new Promise((resolve) => {
  const id = nextId++;
  pending.set(id, resolve);
  worker.postMessage({ id, op, ...data });
});

// ---- small UI helpers --------------------------------------------------------------------
function setStatus(kind, text) {
  status.dataset.kind = kind;
  status.textContent = text;
}

function updateDecryptedOutput(val) {
  inputDecrypted.value = val;
  zeroMd.innerHTML = "";
  if (val) {
    const script = document.createElement("script");
    script.type = "text/markdown";
    script.textContent = val;
    zeroMd.appendChild(script);
  }
}

/** Everything that mirrors the encrypted text: URL, sharing link, copy button, snippets. */
function publishEncrypted(enc) {
  const url = new URL(window.location.href);
  url.searchParams.delete("enc"); // links made by older versions kept it in the query
  url.hash = enc.trim() ? new URLSearchParams({ enc }).toString() : "";
  window.history.replaceState({}, "", url.toString());
  if (enc.trim()) {
    sharingLink.href = url.toString();
    sharingLink.textContent = "Direct link to this message";
    linkGroup.style.display = "flex";
  } else {
    sharingLink.href = "#";
    sharingLink.textContent = "";
    linkGroup.style.display = "none";
  }
  copyBtn.style.display = enc.trim() ? "inline-block" : "none";
  updateSnippets(enc);
}

// ---- shell snippets (ace editors inside tabs) ---------------------------------------------
const snippets = {
  rust: {
    editor: document.getElementById("snippet-rust"), ready: false, text: "",
    intro: "# in a clone of https://github.com/stopsopa/encrypt, after: ./rust/install.sh && ./rust/compile.sh",
    command: "rust/bin/ssenc decrypt",
  },
  node: {
    editor: document.getElementById("snippet-node"), ready: false, text: "",
    intro: "# in a clone of https://github.com/stopsopa/encrypt, Node.js >= 22.18, nothing to install",
    command: "node typescript/dist/cli.ts decrypt",
  },
};

function snippetText(s, enc) {
  if (!enc.trim()) return s.intro + "\n# (type a message and the key above: the command to decrypt it appears here)\n";
  const exact = enc.endsWith("\n");
  return [
    s.intro,
    "# type or paste the key (it is not shown), then press Enter",
    "read -rs SSENC_PASSWORD && export SSENC_PASSWORD",
    "",
    ...(exact ? [] : ["# note: the message does not end with a newline; the heredoc adds one"]),
    s.command + " <<'SSENC_EOF'",
    enc + (exact ? "" : "\n") + "SSENC_EOF",
    "",
  ].join("\n");
}

for (const s of Object.values(snippets)) {
  // An editor in a hidden tab initialises only when its tab is opened; until then the
  // latest text just waits in s.text. Writing .value before onLoad would be thrown away.
  s.editor.addEventListener("onLoad", () => {
    s.ready = true;
    s.editor.value = s.text;
  });
}

function updateSnippets(enc) {
  for (const s of Object.values(snippets)) {
    s.text = snippetText(s, enc);
    if (s.ready) s.editor.value = s.text;
  }
}

// ---- the pipeline ------------------------------------------------------------------------
let generation = 0;
let timer = null;

/** source: which field the user changed ("message" | "key" | "encrypted" | "init"). */
function schedule(source, delay = 200) {
  clearTimeout(timer);
  generation++; // anything still running is now out of date
  timer = setTimeout(() => run(source), delay);
}

async function run(source) {
  const mine = ++generation;
  const stale = () => mine !== generation;
  const key = inputKey.value.trim();
  const message = inputMessage.value;
  let enc = inputEncrypted.value;
  let encryptedNow = false;

  // 1. message + key -> encrypted (not when the user is editing the encrypted field itself)
  if (key && message.trim() && source !== "encrypted" && source !== "init") {
    setStatus("busy", "encrypting…");
    const r = await call("encrypt", { message, password: key, previous: enc.trim() ? enc : undefined });
    if (stale()) return;
    if (!r.ok) {
      setStatus("error", "encryption failed: " + r.message);
      return;
    }
    enc = r.out;
    encryptedNow = true;
    if (inputEncrypted.value !== enc) inputEncrypted.value = enc;
    publishEncrypted(enc);
  }

  // 2. encrypted + key -> decrypted
  if (!enc.trim()) {
    updateDecryptedOutput("");
    setStatus("idle", key ? "type a message, or paste an encrypted one" : "type the key and a message");
    return false;
  }
  if (!key) {
    updateDecryptedOutput("");
    setStatus("idle", "encrypted message loaded — type the key to decrypt it");
    return false;
  }
  setStatus("busy", "decrypting…");
  const d = await call("decrypt", { encrypted: enc, password: key });
  if (stale()) return;
  if (!d.ok) {
    updateDecryptedOutput("");
    setStatus("error", d.kind === "AUTH" ? "cannot decrypt: wrong key, or the encrypted text was modified"
      : d.kind === "MALFORMED" ? "cannot decrypt: this is not a valid ssenc1 encrypted text" : "decryption failed: " + d.message);
    return false;
  }
  updateDecryptedOutput(d.text);
  // The encrypted text came from the URL or was pasted: make the input message match it,
  // so that editing continues from what was decrypted.
  if (!encryptedNow && inputMessage.value !== d.text) inputMessage.value = d.text;
  setStatus("ok", encryptedNow ? "encrypted and verified by decrypting it back" : "decrypted");
  return true;
}

// ---- events ------------------------------------------------------------------------------
inputMessage.addEventListener("input", () => {
  if (!inputMessage.value.trim()) {
    inputEncrypted.value = "";
    publishEncrypted("");
  }
  schedule("message");
});

inputKey.addEventListener("input", async () => {
  const wasEmpty = !inputDecrypted.value.trim();
  clearTimeout(timer);
  // no debounce: a password manager fills the whole key at once
  const ok = await run("key");
  if (ok && wasEmpty) highlightDecrypted();
});

inputEncrypted.addEventListener("input", () => {
  publishEncrypted(inputEncrypted.value);
  schedule("encrypted");
});
inputEncrypted.addEventListener("focus", () => inputEncrypted.select());

$("form").addEventListener("submit", (e) => e.preventDefault());

show.addEventListener("click", () => {
  const secure = inputKey.type === "password";
  inputKey.type = secure ? "text" : "password";
  show.textContent = secure ? "Hide" : "Show";
});

$(".clear").addEventListener("click", () => {
  inputKey.value = "";
  run("key");
});

$(".generate").addEventListener("click", () => {
  const bytes = crypto.getRandomValues(new Uint8Array(24));
  inputKey.value = btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_");
  run("key");
});

$(".encrypt").addEventListener("click", () => run("message"));
$(".decrypt").addEventListener("click", () => run("encrypted"));

$(".lorem-btn").addEventListener("click", () => {
  inputMessage.value = `# Lorem ipsum

Lorem ipsum dolor sit amet, **consectetur** adipiscing elit.

- Etiam molestie pulvinar consequat.
- Phasellus vitae dolor fringilla, elementum risus sit amet, vulputate lorem.
`;
  run("message");
});

async function copyText(text, button) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const dummy = document.createElement("textarea");
    document.body.appendChild(dummy);
    dummy.value = text;
    dummy.select();
    document.execCommand("copy");
    document.body.removeChild(dummy);
  }
  const original = button.textContent;
  button.textContent = "✅ Copied!";
  setTimeout(() => (button.textContent = original), 2000);
}
copyBtn.addEventListener("click", () => copyText(inputEncrypted.value, copyBtn));
copyLinkBtn.addEventListener("click", () => copyText(sharingLink.href, copyLinkBtn));

function highlightDecrypted() {
  const target = document.querySelector("#d");
  target.scrollIntoView({ behavior: "smooth", block: "center" });
  inputDecrypted.classList.remove("highlight-success");
  void inputDecrypted.offsetWidth; // restart the animation
  inputDecrypted.classList.add("highlight-success");
}

// ---- restore state from the URL ------------------------------------------------------------
function encFromUrl() {
  const fromHash = new URLSearchParams(window.location.hash.slice(1)).get("enc");
  return fromHash ?? new URLSearchParams(window.location.search).get("enc") ?? "";
}

async function restore() {
  const enc = encFromUrl();
  if (enc) inputEncrypted.value = enc;
  publishEncrypted(inputEncrypted.value);
  // The key may already be there (browser autofill, back/forward cache).
  const ok = await run(enc ? "init" : "message");
  if (ok && enc) highlightDecrypted();
}
window.addEventListener("hashchange", () => {
  const enc = encFromUrl();
  if (enc && enc !== inputEncrypted.value) {
    inputEncrypted.value = enc;
    publishEncrypted(enc);
    run("init");
  }
});
restore();

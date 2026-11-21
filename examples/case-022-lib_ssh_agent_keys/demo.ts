// case-022: ssh keys held by ssh-agent as encryption keys. ts.sh starts a private agent
// with the demo keys and sets SSH_AUTH_SOCK before it runs this file.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { decryptToString, encrypt, inspect, rekey, sshFingerprint, sshKeyType, sshParsePublicKey } from "../../typescript/dist/ssenc.node.ts";

const plain = "API_KEY=8f2c1d\nDB_PASSWORD=hunter2\n";

// --- an ssh key is named by the content of its PUBLIC key file --------------------------
// The private key stays in the agent: the library asks the agent for a signature and
// derives the encryption key from it.
const ed25519Pub = readFileSync("tmp/demo_ed25519.pub", "utf8");
const sshKey = { type: "ssh", publicKey: ed25519Pub } as const;
const encrypted = await encrypt(plain, sshKey);
console.log("encrypted for the Ed25519 key:\n" + encrypted);
assert.equal(await decryptToString(encrypted, sshKey), plain);
console.log("decrypted with the same key: ok");

// --- helpers: key blob, key type, fingerprint (as printed by ssh-add -l) ----------------
const blob = sshParsePublicKey(ed25519Pub);
const fingerprint = await sshFingerprint(blob);
console.log(`\nkey type ${sshKeyType(blob)}, fingerprint ${fingerprint}`);

// --- the key can be named by fingerprint alone; it is then looked up in the agent -------
assert.equal(await decryptToString(encrypted, { type: "ssh", fingerprint }), plain);
console.log("decrypted with the key named by fingerprint: ok");

// --- agentSocket: use a specific agent instead of $SSH_AUTH_SOCK ------------------------
const socket = process.env.SSH_AUTH_SOCK;
assert.equal(await decryptToString(encrypted, { type: "ssh", publicKey: ed25519Pub, agentSocket: socket }), plain);
console.log(`decrypted through an explicitly named agent socket (${socket}): ok`);

// --- several keys: two ssh keys and a backup password; any one opens the text -----------
const rsaKey = { type: "ssh", publicKey: readFileSync("tmp/demo_rsa.pub", "utf8") } as const;
const backup = { type: "password", password: readFileSync("tmp/backup-password.txt", "utf8").trim() } as const;
const shared = await encrypt(plain, [sshKey, rsaKey, backup]);
console.log("\nthree key slots:", inspect(shared).slots);
for (const key of [sshKey, rsaKey, backup]) assert.equal(await decryptToString(shared, key), plain);
console.log("each of the three keys opens it: ok");

// --- stable updates work with an ssh key as with a password -----------------------------
const updated = await encrypt(plain + "REGION=eu-west-1\n", rsaKey, { previous: shared });
assert.equal(updated.split("\n").filter((line) => !shared.split("\n").includes(line)).length, 1);
assert.equal(inspect(updated).slots.length, 3);
console.log("update made with one key: one new line, all three key slots kept: ok");

// --- rekey from a password to an ssh key -------------------------------------------------
const onlySsh = await rekey(shared, backup, sshKey);
console.log("after rekey to the ssh key only:", inspect(onlySsh).slots);
await assert.rejects(decryptToString(onlySsh, backup), { kind: "AUTH" });

// --- what does not work ------------------------------------------------------------------
// A key that is not loaded in the agent: ENV.
await assert.rejects(decryptToString(encrypted, { type: "ssh", fingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" }), { kind: "ENV" });
console.log("\na key that is not in the agent is rejected (ENV): ok");

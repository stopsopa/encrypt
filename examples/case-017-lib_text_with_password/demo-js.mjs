// case-017: the same library as plain JavaScript (for Node.js versions that cannot run
// TypeScript, or projects without TypeScript) and as the browser build.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import * as nodeBuild from "../../typescript/dist/ssenc.node.js";
// The browser build uses only WebCrypto, so Node.js can load it too. In a page:
//   <script type="module"> import { encrypt } from "./ssenc.browser.js"; </script>
import * as browserBuild from "../../typescript/dist/ssenc.browser.js";

const key = { type: "password", password: readFileSync("tmp/password.txt", "utf8").trim() };

const encrypted = await nodeBuild.encrypt("made by the Node.js build\n", key);
console.log(`build "${nodeBuild.BUILD}" encrypted:\n${encrypted}`);

const text = await browserBuild.decryptToString(encrypted, key);
console.log(`build "${browserBuild.BUILD}" decrypted: ${text}`);
assert.equal(text, "made by the Node.js build\n");

// Both builds export the same names.
assert.deepEqual(Object.keys(nodeBuild).sort(), Object.keys(browserBuild).sort());
console.log("both builds export:", Object.keys(nodeBuild).sort().join(", "));

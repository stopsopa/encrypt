// Deterministic test inputs. Generated in memory (and written to out/fixtures/ for
// inspection), never committed: the large ones are megabytes of pseudo-random bytes.
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { OUT } from "./common.ts";

export type Fixture = { name: string; about: string; data: Buffer; kind: "text" | "small-binary" | "large-binary" };

function prng(seed: number): () => number {
  let s = seed >>> 0 || 1;
  return () => {
    s ^= s << 13; s >>>= 0;
    s ^= s >>> 17;
    s ^= s << 5; s >>>= 0;
    return s & 255;
  };
}

function randomBytes(n: number, seed: number): Buffer {
  const next = prng(seed);
  const b = Buffer.alloc(n);
  for (let i = 0; i < n; i++) b[i] = next();
  return b;
}

const CONFIG = `# database
server:
  host: db.internal
  port: 5432
  user: app
  password: "s3cr3t-value"
cache:
  host: cache.internal
  ttl: 300
features:
  - signup
  - billing
  - export
logging:
  level: info
  file: /var/log/app.log
`;

const t = (s: string): Buffer => Buffer.from(s, "utf8");

export const FIXTURES: Fixture[] = [
  { name: "empty", about: "0 bytes", data: Buffer.alloc(0), kind: "text" },
  { name: "one-line", about: "single line, no trailing newline", data: t("hello world"), kind: "text" },
  { name: "only-newlines", about: "three empty lines", data: t("\n\n\n"), kind: "text" },
  { name: "text-lf", about: "config file, LF line endings", data: t(CONFIG), kind: "text" },
  { name: "text-crlf", about: "same file with CRLF line endings, last line unterminated", data: t(CONFIG.replace(/\n/g, "\r\n") + "end"), kind: "text" },
  {
    name: "whitespace", about: "tabs, mixed indentation, trailing spaces, whitespace-only lines",
    data: t("no indent\n  two spaces\n\ttab\n \t mixed \t \n    trailing spaces    \n\t\ttrailing tab\t\n   \n\t\n\n  inner   spaces\tand\ttabs  \n \n  last line no newline  "),
    kind: "text",
  },
  { name: "duplicates", about: "repeated lines", data: t("}\n}\n  }\n}\nreturn x;\nreturn x;\n\n\n}\n"), kind: "text" },
  { name: "utf8", about: "multi-byte UTF-8, emoji, non-breaking space", data: t("zażółć gęślą jaźń\n  日本語のテキスト  \n nbsp is not stripped \n👩‍💻 emoji 🔐\n em space \n"), kind: "text" },
  {
    name: "invalid-utf8", about: "lines containing bytes that are not valid UTF-8",
    data: Buffer.concat([t("ok line\n"), Buffer.from([0xff, 0xfe, 0x41, 0x80, 0x0a]), t("  "), Buffer.from([0xc3, 0x28, 0xf0, 0x9f]), t("  \n"), Buffer.from([0xed, 0xa0, 0x80])]),
    kind: "text",
  },
  {
    name: "long-line", about: "one 64 KiB line between short lines",
    data: Buffer.concat([t("short\n"), Buffer.from(randomBytes(65536, 7).map((b) => 33 + (b % 94))), t("\nshort again\n")]),
    kind: "text",
  },
  {
    name: "header-lookalike", about: "plaintext lines that look like ssenc1 header lines",
    data: t("#ssenc1 lines ws=1 pad=16\n#slot pw argon2id m=8,t=1,p=1 AAAAAAAAAAAAAAAAAAAAAA AAAA\n#seal AAAA\n  #slot ssh x\n#ssenc1 blob chunk=1\n"),
    kind: "text",
  },
  { name: "binary-nul", about: "every byte value 0..255, four times (includes NUL, CR, LF)", data: Buffer.from(Uint8Array.from({ length: 1024 }, (_, i) => i & 255)), kind: "small-binary" },
  { name: "bin-1", about: "1 byte (0x00)", data: Buffer.from([0]), kind: "small-binary" },
  { name: "bin-65535", about: "random, one byte less than a blob chunk", data: randomBytes(65535, 11), kind: "large-binary" },
  { name: "bin-65536", about: "random, exactly one blob chunk", data: randomBytes(65536, 12), kind: "large-binary" },
  { name: "bin-65537", about: "random, one byte more than a blob chunk", data: randomBytes(65537, 13), kind: "large-binary" },
  { name: "bin-1MiB", about: "1 MiB random (16 blob chunks)", data: randomBytes(1048576, 14), kind: "large-binary" },
];

export function fixture(name: string): Fixture {
  const f = FIXTURES.find((x) => x.name === name);
  if (!f) throw new Error("unknown fixture " + name);
  return f;
}

export function writeFixtures(): void {
  const dir = join(OUT, "fixtures");
  mkdirSync(dir, { recursive: true });
  for (const f of FIXTURES) writeFileSync(join(dir, f.name + ".bin"), f.data);
}

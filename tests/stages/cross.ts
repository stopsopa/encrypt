// Stages 1-3: every participant encrypts every case into a file, then every participant
// decrypts every file.
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { Check, Participant } from "../lib/common.ts";
import { OUT, compareOutput, tail } from "../lib/common.ts";
import { CASES } from "../lib/cases.ts";
import { fixture } from "../lib/fixtures.ts";

export function artifactPath(producer: string, caseId: string): string {
  return join(OUT, "artifacts", producer, caseId + ".enc");
}

export function readArtifact(producer: string, caseId: string): Buffer | null {
  const p = artifactPath(producer, caseId);
  return existsSync(p) ? readFileSync(p) : null;
}

export function encryptChecks(producers: Participant[]): Check[] {
  const checks: Check[] = [];
  for (const p of producers) {
    mkdirSync(join(OUT, "artifacts", p.id), { recursive: true });
    for (const c of CASES) {
      checks.push({
        id: "encrypt." + p.id + "." + c.id, suite: "encrypt",
        title: p.id + " encrypts input '" + c.fixture + "' (" + fixture(c.fixture).about + "), mode " + c.mode + ", key " + c.key,
        producer: p.id, case: c.id, fixture: c.fixture, mode: c.mode, key: c.key,
        run: async () => {
          const r = await p.run({ cmd: "encrypt", input: fixture(c.fixture).data, key: c.encryptKey, opts: c.opts });
          if (r.kind !== "OK") return { status: "fail", ms: r.ms, detail: "encrypt failed with " + r.kind + ": " + tail(r.stderr) };
          const wantHeader = c.mode === "blob" ? "#ssenc1 blob chunk=65536\n" : "#ssenc1 lines ws=" + (c.mode === "lines-ws1" ? 1 : 0) + " pad=16\n";
          if (!r.output.toString("latin1").startsWith(wantHeader)) {
            return { status: "fail", ms: r.ms, expected: wantHeader.trim(), actual: r.output.subarray(0, 40).toString("latin1"), detail: "unexpected header line" };
          }
          if (r.output.some((b) => b > 126 || (b < 32 && b !== 10 && b !== 13 && b !== 9))) {
            return { status: "fail", ms: r.ms, detail: "output is not plain ASCII text" };
          }
          writeFileSync(artifactPath(p.id, c.id), r.output);
          return { status: "pass", ms: r.ms };
        },
      });
    }
  }
  return checks;
}

export function crossChecks(all: Participant[]): Check[] {
  const checks: Check[] = [];
  for (const producer of all) {
    for (const consumer of all) {
      for (const c of CASES) {
        c.decryptKeys.forEach((dk, i) => {
          checks.push({
            id: "cross." + producer.id + "." + consumer.id + "." + c.id + (c.decryptKeys.length > 1 ? "." + i : ""),
            suite: "cross",
            title: consumer.id + " decrypts a file encrypted by " + producer.id + ": input '" + c.fixture + "' (" + fixture(c.fixture).about + "), mode " + c.mode + ", key " + dk.label,
            producer: producer.id, consumer: consumer.id, case: c.id, fixture: c.fixture, mode: c.mode, key: dk.label,
            run: async () => {
              const artifact = readArtifact(producer.id, c.id);
              const rel = "artifacts/" + producer.id + "/" + c.id + ".enc";
              if (!artifact) return { status: "fail", detail: "no encrypted file: " + producer.id + " failed to encrypt this case" };
              const out = compareOutput(await consumer.run({ cmd: "decrypt", input: artifact, key: dk.key }), fixture(c.fixture).data);
              if (out.status !== "pass") out.artifact = rel;
              return out;
            },
          });
        });
      }
    }
  }
  return checks;
}

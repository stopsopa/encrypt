// Cross-implementation test runner.
//
//   stage 0  unit tests of each language            (<lang>/test.sh)
//   stage 1  server participants encrypt every case  -> out/artifacts/<producer>/<case>.enc
//   stage 2  the browser encrypts every case         -> out/artifacts/browser-js/<case>.enc
//   stage 3  every participant decrypts every file
//   stage 4  vectors, rekey, diff stability, negative tests
//
// Writes out/checks.json (everything that is supposed to run, written BEFORE running, so
// the report can show a check that never produced a result as "missing"), out/results.jsonl
// and out/meta.json. Exit code 0 only if every planned check passed.
//
//   node tests/run.ts [--only rust,node-ts,...] [--skip-unit] [--suite cross,negative,...]
import { spawn, execFileSync } from "node:child_process";
import { appendFileSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { arch, platform, release } from "node:os";
import { join } from "node:path";
import type { Check, Outcome, Participant } from "./lib/common.ts";
import { OUT, ROOT, tail } from "./lib/common.ts";
import { CASES } from "./lib/cases.ts";
import { FIXTURES, writeFixtures } from "./lib/fixtures.ts";
import { startParticipants } from "./lib/participants.ts";
import { crossChecks, encryptChecks } from "./stages/cross.ts";
import { diffChecks, inspectChecks, negativeChecks, rekeyChecks, vectorChecks } from "./stages/extra.ts";

const argv = process.argv.slice(2);
const argValue = (name: string): string | undefined => {
  const i = argv.indexOf(name);
  return i >= 0 ? argv[i + 1] : undefined;
};
const only = argValue("--only")?.split(",");
const suites = argValue("--suite")?.split(",");
const skipUnit = argv.includes("--skip-unit");

function sh(cmd: string, args: string[]): string {
  try {
    return execFileSync(cmd, args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
  } catch (e) {
    const err = e as { stderr?: string; stdout?: string };
    return (err.stderr || err.stdout || "").trim() || "not available";
  }
}

function unitChecks(): Check[] {
  const langs: [string, string, string[]][] = [["rust", "rust", ["rust"]], ["bash", "bash", ["bash"]], ["typescript", "typescript", ["node-ts", "node-js", "browser-js"]]];
  return langs.filter(([, , ids]) => !only || ids.some((i) => only.includes(i))).map(([lang, dir]) => ({
    id: "unit." + lang, suite: "unit" as const, title: lang + "/test.sh (unit tests of the " + lang + " implementation)", consumer: lang, case: lang + "/test.sh",
    run: (): Promise<Outcome> => new Promise((resolve) => {
      const t0 = performance.now();
      const env = { ...process.env };
      delete env.NODE_OPTIONS;
      const child = spawn(join(ROOT, dir, "test.sh"), [], { env, stdio: ["ignore", "pipe", "pipe"] });
      let out = "";
      child.stdout.on("data", (d: Buffer) => (out += d.toString()));
      child.stderr.on("data", (d: Buffer) => (out += d.toString()));
      child.on("error", (e) => resolve({ status: "fail", detail: String(e) }));
      child.on("close", (code) => resolve({
        status: code === 0 ? "pass" : "fail", ms: performance.now() - t0,
        detail: tail(out.replace(/\x1b\[[0-9;]*m/g, ""), code === 0 ? 400 : 3000),
      }));
    }),
  }));
}

async function runStage(name: string, checks: Check[], concurrency: number): Promise<{ pass: number; fail: number }> {
  const t0 = performance.now();
  let pass = 0, fail = 0, next = 0;
  const worker = async (): Promise<void> => {
    for (;;) {
      const check = checks[next++];
      if (!check) return;
      let outcome: Outcome;
      try {
        outcome = await check.run();
      } catch (e) {
        outcome = { status: "fail", detail: "test runner error: " + (e instanceof Error ? e.stack : String(e)) };
      }
      if (outcome.status === "fail") {
        fail++;
        console.log("  FAIL " + check.id + "\n       " + (outcome.detail ?? "").split("\n").join("\n       "));
      } else pass++;
      appendFileSync(join(OUT, "results.jsonl"), JSON.stringify({ id: check.id, ...outcome, ms: outcome.ms === undefined ? undefined : Math.round(outcome.ms) }) + "\n");
    }
  };
  await Promise.all(Array.from({ length: Math.min(concurrency, Math.max(1, checks.length)) }, worker));
  console.log(`${name}: ${pass} passed, ${fail} failed (${checks.length} checks, ${((performance.now() - t0) / 1000).toFixed(1)} s)`);
  return { pass, fail };
}

rmSync(OUT, { recursive: true, force: true });
mkdirSync(OUT, { recursive: true });
writeFixtures();

const participants = await startParticipants(only);
let exitCode = 1;
try {
  console.log("participants:");
  for (const p of participants.all) console.log("  " + p.id.padEnd(11) + participants.versions[p.id]);
  const broken = participants.all.filter((p) => /^(MISSING|BROKEN)/.test(participants.versions[p.id]));
  if (broken.length) console.log("WARNING: not runnable (their checks will fail): " + broken.map((p) => p.id).join(", "));

  const want = (s: string): boolean => !suites || suites.includes(s);
  const stages: { name: string; checks: Check[]; concurrency: number }[] = [
    { name: "stage 0  unit tests", checks: skipUnit || !want("unit") ? [] : unitChecks(), concurrency: 1 },
    { name: "stage 1  server encrypt", checks: encryptChecks(participants.server), concurrency: 16 },
    { name: "stage 2  browser encrypt", checks: encryptChecks(participants.browser), concurrency: 4 },
    { name: "stage 3  decrypt all with all", checks: want("cross") ? crossChecks(participants.all) : [], concurrency: 24 },
    {
      name: "stage 4  vectors, rekey, diff, negative",
      checks: [
        ...(want("vectors") ? [...vectorChecks(participants.all), ...inspectChecks(participants.all)] : []),
        ...(want("rekey") ? rekeyChecks(participants.all) : []),
        ...(want("diff") ? diffChecks(participants.all) : []),
        ...(want("negative") ? negativeChecks(participants.all) : []),
      ],
      concurrency: 24,
    },
  ];

  const allChecks = stages.flatMap((s) => s.checks);
  const ids = new Set<string>();
  for (const c of allChecks) {
    if (ids.has(c.id)) throw new Error("duplicate check id " + c.id);
    ids.add(c.id);
  }
  writeFileSync(join(OUT, "checks.json"), JSON.stringify(allChecks.map(({ run: _run, ...rest }) => rest)));
  writeFileSync(join(OUT, "results.jsonl"), "");
  const env = process.env;
  writeFileSync(join(OUT, "meta.json"), JSON.stringify({
    os: env.SSENC_OS_LABEL ?? platform() + "-" + arch(),
    osDetail: platform() + " " + release() + " " + arch(),
    date: new Date().toISOString(),
    commit: env.GITHUB_SHA ?? sh("git", ["-C", ROOT, "rev-parse", "HEAD"]),
    dirty: env.GITHUB_SHA ? false : sh("git", ["-C", ROOT, "status", "--porcelain"]) !== "",
    branch: env.GITHUB_REF_NAME ?? sh("git", ["-C", ROOT, "rev-parse", "--abbrev-ref", "HEAD"]),
    runUrl: env.GITHUB_RUN_ID ? `${env.GITHUB_SERVER_URL}/${env.GITHUB_REPOSITORY}/actions/runs/${env.GITHUB_RUN_ID}` : null,
    runNumber: env.GITHUB_RUN_NUMBER ?? null,
    repoUrl: env.GITHUB_REPOSITORY ? `${env.GITHUB_SERVER_URL}/${env.GITHUB_REPOSITORY}` : null,
    filter: { only: only ?? null, suites: suites ?? null, skipUnit },
    versions: {
      node: process.version,
      rustc: sh("rustc", ["--version"]),
      bash: sh("bash", ["-c", "echo $BASH_VERSION"]),
      openssl: sh("openssl", ["version"]),
      ssh: sh("ssh", ["-V"]),
      browser: participants.browser.length ? (participants.browser[0] as Participant & { browserVersion: string }).browserVersion : "not run",
    },
    participants: participants.all.map((p) => ({ id: p.id, what: p.what, where: p.where, how: p.how, version: participants.versions[p.id] })),
    fixtures: FIXTURES.map((f) => ({ name: f.name, about: f.about, bytes: f.data.length })),
    cases: CASES.length,
  }, null, 1));

  let fail = 0;
  for (const s of stages) {
    if (s.checks.length === 0) continue;
    fail += (await runStage(s.name, s.checks, s.concurrency)).fail;
  }
  console.log(fail === 0 ? `ALL ${allChecks.length} CHECKS PASSED` : `${fail} of ${allChecks.length} CHECKS FAILED`);
  exitCode = fail === 0 ? 0 : 1;
} finally {
  await Promise.all(participants.all.map((p) => p.close()));
}
process.exit(exitCode);

// Builds the static HTML report from one or more test runs.
//
//   node tests/report/build.ts                         tests/out  ->  tests/out/report
//   node tests/report/build.ts --input DIR --input DIR2 --output SITE     (CI: one DIR per OS)
//
// A check listed in checks.json without a line in results.jsonl is reported as "missing"
// and counts as a failure, so a run that crashed half way can never look green.
// Exit code: 0 always (building the report is not the test verdict); use --strict to exit 1
// when any run has failures.
import { copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const argv = process.argv.slice(2);
const inputs: string[] = [];
let output = "";
let strict = false;
for (let i = 0; i < argv.length; i++) {
  if (argv[i] === "--input") inputs.push(argv[++i]);
  else if (argv[i] === "--output") output = argv[++i];
  else if (argv[i] === "--strict") strict = true;
  else throw new Error("unknown argument " + argv[i]);
}
if (inputs.length === 0) inputs.push(join(here, "..", "out"));
if (!output) output = join(inputs[0], "report");
mkdirSync(output, { recursive: true });

type Row = Record<string, unknown> & { id: string; status: string; artifact?: string };
const runs: { meta: Record<string, unknown>; checks: Row[] }[] = [];
let failures = 0;

for (const dir of inputs) {
  if (!existsSync(join(dir, "checks.json")) || !existsSync(join(dir, "meta.json"))) {
    // The run did not even get to planning its checks: show that as a failed run.
    runs.push({
      meta: { os: (dir.split("/").filter(Boolean).pop() ?? "run").replace(/^results-/, ""), broken: "no results were produced (the test run crashed before it started; see the CI log)", versions: {}, participants: [], fixtures: [] },
      checks: [{ id: "run", suite: "unit", title: "test run produced results", status: "missing" }],
    });
    failures++;
    continue;
  }
  const meta = JSON.parse(readFileSync(join(dir, "meta.json"), "utf8"));
  const checks: Row[] = JSON.parse(readFileSync(join(dir, "checks.json"), "utf8"));
  const results = new Map<string, Record<string, unknown>>();
  if (existsSync(join(dir, "results.jsonl"))) {
    for (const line of readFileSync(join(dir, "results.jsonl"), "utf8").split("\n")) {
      if (line.trim()) {
        const r = JSON.parse(line);
        results.set(r.id, r);
      }
    }
  }
  for (const c of checks) {
    const r = results.get(c.id);
    if (r) Object.assign(c, r);
    else {
      c.status = "missing";
      c.detail = "this check was planned but produced no result (the run stopped before reaching it)";
    }
    if (c.status !== "pass" && c.status !== "skipped") failures++;
    if (c.status !== "pass" && typeof c.artifact === "string" && existsSync(join(dir, c.artifact))) {
      const rel = join("artifacts", String(meta.os), c.artifact.replace(/^artifacts\//, ""));
      mkdirSync(dirname(join(output, rel)), { recursive: true });
      copyFileSync(join(dir, c.artifact), join(output, rel));
      c.artifact = rel;
    } else delete c.artifact;
  }
  runs.push({ meta, checks });
}

const data = { generated: new Date().toISOString(), runs };
const json = JSON.stringify(data);
writeFileSync(join(output, "results.json"), json);
const html = readFileSync(join(here, "template.html"), "utf8").replace("/*__DATA__*/null", () => json.replace(/</g, "\\u003c"));
writeFileSync(join(output, "index.html"), html);
writeFileSync(join(output, ".nojekyll"), "");
const total = runs.reduce((n, r) => n + r.checks.length, 0);
console.log(`report: ${join(output, "index.html")}  (${runs.length} run(s), ${total} checks, ${failures} not passing)`);
process.exit(strict && failures > 0 ? 1 : 0);

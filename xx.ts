// Menu of project commands for xx (https://github.com/stopsopa/xx).
//   xx                 interactive menu
//   xx <name> [args]   run one command
// Every command is a thin wrapper around a script in the repository, so the same thing can
// always be run without xx (the script path is in each description).

type Command = { command: string; description?: string; confirm?: boolean; source?: boolean; order?: number };

const PARTS = ["typescript", "rust", "bash", "tests"] as const;

const run = (script: string): string => `
set -e
./${script} "\${@}"
`;

export default (setup: Record<string, Command>) => {
  const commands: Record<string, Command> = {};
  let order = 10;
  const add = (name: string, script: string, description: string): void => {
    commands[name] = { command: run(script), description: `${description}  [./${script}]`, confirm: false, order: order++ };
  };

  // --- everything ---
  add("envverify", "envverify.sh", "check that all tools needed to compile and test are present (all parts)");
  add("install", "install.sh", "install dependencies of all parts");
  add("compile", "compile.sh", "compile all implementations");
  add("test", "test.sh", "run ALL tests: unit tests + cross matrix incl. browser, then build the report. Args: --only rust,bash,node-ts,node-js,browser-js  --skip-unit  --suite cross,vectors,rekey,diff,negative  --verbose (one line per passing check)");

  // --- per part ---
  for (const part of PARTS) {
    add(`${part} envverify`, `${part}/envverify.sh`, `check the environment for ${part}`);
    add(`${part} install`, `${part}/install.sh`, `install dependencies for ${part}`);
    if (part !== "tests") {
      add(`${part} compile`, `${part}/compile.sh`, `compile ${part}`);
      add(`${part} test`, `${part}/test.sh`, `unit tests of the ${part} implementation only`);
    }
  }

  // --- report ---
  commands["report build"] = {
    command: `
set -e
unset NODE_OPTIONS
node --disable-warning=ExperimentalWarning tests/report/build.ts "\${@}"
`,
    description: "rebuild tests/out/report/index.html from the results of the last test run  [tests/report/build.ts]",
    confirm: false,
    order: order++,
  };
  commands["report open"] = {
    command: `
set -e
if [ ! -f tests/out/report/index.html ]; then
  echo "no report yet: run 'xx test' first" >&2
  exit 1
fi
if command -v open >/dev/null 2>&1; then open tests/out/report/index.html; else xdg-open tests/out/report/index.html; fi
`,
    description: "open the HTML report of the last local test run in the browser",
    confirm: false,
    order: order++,
  };
  commands["encryptor serve"] = {
    command: `
set -e
PORT="\${1:-8080}"
echo "encryptor page: http://127.0.0.1:\${PORT}/encryptor/   (Ctrl+C to stop)"
python3 -m http.server "\${PORT}" --bind 127.0.0.1
`,
    description: "serve the encryptor page locally (it needs http, not file://). Optional argument: port, default 8080  [encryptor/index.html]",
    confirm: false,
    order: order++,
  };
  commands["vectors regenerate"] = {
    command: `
set -e
unset NODE_OPTIONS
eval "\$(tests/lib/agent.sh start)"
trap 'tests/lib/agent.sh stop' EXIT
node --disable-warning=ExperimentalWarning tests/vectors/generate.ts
`,
    description: "REWRITES the known-answer vectors in tests/vectors/ with the TypeScript implementation. Only after a deliberate format change  [tests/vectors/generate.ts]",
    order: order++,
  };

  return { ...commands, ...setup };
};

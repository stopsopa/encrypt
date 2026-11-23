// Menu of project commands for xx (https://github.com/stopsopa/xx).
//   xx                 interactive menu
//   xx <name> [args]   run one command
// Every command is a thin wrapper around a script in the repository, so the same thing can
// always be run without xx (the script path is in each description).
//
// Every command is written out in full, one entry per command, in the order of the menu. The only
// loop is for the "typescript / rust / bash" commands, identical except for the name of the part.

type Command = {
  command: string;
  description?: string;
  confirm?: boolean;
  source?: boolean;
  order?: number;
};

export default (setup: Record<string, Command>): Record<string, Command> => {
  // Commands are defined in the same order as they are shown in the menu.
  let commands: Record<string, Command> = {
    // --- everything ---
    [`envverify`]: {
      command: `
set -e
./envverify.sh "\${@}"
`,
      description: `check that all tools needed to compile and test are present (all parts)  [./envverify.sh]`,
      confirm: false,
      order: 10,
    },
    [`install`]: {
      command: `
set -e
./install.sh "\${@}"
`,
      description: `install dependencies of all parts  [./install.sh]`,
      confirm: false,
      order: 11,
    },
    [`compile`]: {
      command: `
set -e
./compile.sh "\${@}"
`,
      description: `compile all implementations  [./compile.sh]`,
      confirm: false,
      order: 12,
    },
    [`test`]: {
      command: `
set -e
mkdir -p var
./test.sh "\${@}" | tee var/test.log
`,
      description: `run ALL tests: unit tests + cross matrix incl. browser, then build the report. Args: --only rust,bash,node-ts,node-js,browser-js  --skip-unit  --suite cross,vectors,rekey,diff,negative  --verbose (one line per passing check)  [./test.sh]`,
      confirm: false,
      order: 13,
    },
  };

  // --- typescript / rust / bash ---
  // The three implementations have the same four commands each, so they are defined once, in a loop.
  // Each pass builds a helper object, written like any other group of commands (only the name of the
  // part is a variable), and merges it into the main one.
  let order = 14; // 14-25: after the "everything" group, before "tests"
  for (const part of [`typescript`, `rust`, `bash`]) {
    const helper: Record<string, Command> = {
      [`${part} envverify`]: {
        command: `
set -e
./${part}/envverify.sh "\${@}"
`,
        description: `check the environment for ${part}  [./${part}/envverify.sh]`,
        confirm: false,
        order: order++,
      },
      [`${part} install`]: {
        command: `
set -e
./${part}/install.sh "\${@}"
`,
        description: `install dependencies for ${part}  [./${part}/install.sh]`,
        confirm: false,
        order: order++,
      },
      [`${part} compile`]: {
        command: `
set -e
./${part}/compile.sh "\${@}"
`,
        description: `compile ${part}  [./${part}/compile.sh]`,
        confirm: false,
        order: order++,
      },
      [`${part} test`]: {
        command: `
set -e
./${part}/test.sh "\${@}"
`,
        description: `unit tests of the ${part} implementation only  [./${part}/test.sh]`,
        confirm: false,
        order: order++,
      },
    };

    commands = { ...commands, ...helper };
  }

  commands = {
    ...commands,

    // --- tests (cross-implementation suite) ---
    [`tests envverify`]: {
      command: `
set -e
./tests/envverify.sh "\${@}"
`,
      description: `check the environment for tests  [./tests/envverify.sh]`,
      confirm: false,
      order: 26,
    },
    [`tests install`]: {
      command: `
set -e
./tests/install.sh "\${@}"
`,
      description: `install dependencies for tests  [./tests/install.sh]`,
      confirm: false,
      order: 27,
    },

    // --- examples ---
    [`examples`]: {
      command: `
set -e
./examples/examples.sh "\${@}"
`,
      description: `run ALL usage examples (examples/case-*/ in the rust, ts and bash variant); they check their own results. Args: text filters like 011 or ssh, --lang rust,ts,bash  --quiet (summary only)  --list  [./examples/examples.sh]`,
      confirm: false,
      order: 28,
    },

    // --- report ---
    [`report build`]: {
      command: `
set -e
unset NODE_OPTIONS
node --disable-warning=ExperimentalWarning tests/report/build.ts "\${@}"
`,
      description: `rebuild tests/out/report/index.html from the results of the last test run  [tests/report/build.ts]`,
      confirm: false,
      order: 29,
    },
    [`report open`]: {
      command: `
set -e
if [ ! -f tests/out/report/index.html ]; then
  echo "no report yet: run 'xx test' first" >&2
  exit 1
fi
if command -v open >/dev/null 2>&1; then open tests/out/report/index.html; else xdg-open tests/out/report/index.html; fi
`,
      description: `open the HTML report of the last local test run in the browser`,
      confirm: false,
      order: 30,
    },

    // --- other ---
    [`encryptor serve`]: {
      command: `
set -e
PORT="\${1:-8080}"
echo "encryptor page: http://127.0.0.1:\${PORT}/encryptor/   (Ctrl+C to stop)"
python3 -m http.server "\${PORT}" --bind 127.0.0.1
`,
      description: `serve the encryptor page locally (it needs http, not file://). Optional argument: port, default 8080  [encryptor/index.html]`,
      confirm: false,
      order: 31,
    },
    [`vectors regenerate`]: {
      command: `
set -e
unset NODE_OPTIONS
eval "\$(tests/lib/agent.sh start)"
trap 'tests/lib/agent.sh stop' EXIT
node --disable-warning=ExperimentalWarning tests/vectors/generate.ts
`,
      description: `REWRITES the known-answer vectors in tests/vectors/ with the TypeScript implementation. Only after a deliberate format change  [tests/vectors/generate.ts]`,
      order: 32,
    },
  };

  return { ...commands, ...setup };
};

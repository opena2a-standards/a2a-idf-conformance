# Testing another implementation

Part of [Reference verifiers and suite tooling](../scripts/README.md).

An A2A-IDF implementation joins the parity gate with `--verifier NAME=COMMAND`, which can be given more than once. The gate runs the implementation beside the two reference verifiers. It compares the implementation with them and with the outcome pinned in each fixture:

```bash
python3 scripts/parity/parity.py --verifier mylib="node ../mylib/conformance.js" --json parity-report.json
```

## The interface

An implementation provides this interface:

- **Invocation.** COMMAND is split with shell-style quoting; no shell is invoked. It runs from the directory `parity.py` is called from, with the absolute path of this repository's `fixtures/` directory appended as its last argument. The implementation walks that directory recursively for `*.json` and evaluates every fixture.
- **Output.** On stdout, one block per fixture in the [reference verifier format](./verifiers.md#output). A block starts with a line `PASS <path>`, `FAIL <path>` or `ERROR <path>`. For `PASS` and `FAIL`, an indented line `observed: ACCEPT` or `observed: REJECT[CATEGORY]` follows. `CATEGORY` is in upper case, letters and underscores, as in `rejectCategory`. Other lines are ignored.
- **Paths.** `<path>` is the fixture path the implementation was given (absolute). It can also be any path whose last `fixtures` directory component is followed by the path under `fixtures/`. `fixtures/levels/x.json` and `/any/checkout/fixtures/levels/x.json` both name `levels/x.json`. `my-fixtures/levels/x.json` does not, because `my-fixtures` is a different directory name.
- **Lines.** A line ends at a line feed, and a carriage return also ends one. A line or paragraph separator (U+2028, U+2029) in a quoted fixture value does not.
- **Gate status.** `PASS` when the observed outcome matches the fixture's `expected` block (`verifyResult`, and `rejectCategory` when present). `FAIL` when it does not. `ERROR` when the implementation could not reach a verdict.
- **Exit code.** 0 when every fixture is `PASS`, non-zero otherwise.

## What the gate reports

The gate reports `PARITY: FAIL` and exits 1 when any verifier:

- exits non-zero or cannot be started;
- misses a fixture, or reports one that does not exist;
- disagrees with another verifier on gate status, verdict or reject category;
- observes an outcome other than the one pinned in the fixture.

Each `ERROR` a verifier reports is also a divergence line of its own. That line carries the reason line the verifier printed under the `ERROR`.

The pinned check reads each fixture's `expected` block directly. So an implementation that prints `PASS` next to the wrong verdict still fails. A fixture whose `expected` block is not a JSON object pins nothing, so the gate reports it as a divergence too.

A command that cannot be started is reported once, as `<name> verifier exited 127 (expected 0)` with the reason on stderr. It is not also reported as missing every fixture.

## Usage errors and the report file

These are usage errors, with exit code 2:

- a verifier name already in use (`node`, `python`, or an earlier `--verifier`);
- a `--json` path that cannot be written: in a directory that does not exist, a directory, or one without write permission. It is refused before any verifier runs;
- an option not spelled in full: `--jso` is refused, not taken for `--json`.

`--help`, `-h` and a usage error in the other arguments end the run before the `--json` path is opened. So they leave it as it was. An existing file keeps its content until the new report is written in its place.

With `--json` given more than once, the gate opens and writes only the last path. It names that path on stderr before the run, as in `[parity] --json given 2 times: the report is written to 'b.json' only`.

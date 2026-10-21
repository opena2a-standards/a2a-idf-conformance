# Contributor tools

Part of [Reference verifiers and suite tooling](../scripts/README.md).

Three scripts maintain the suite: the fixture generator, the conformance profile script and the documentation path check. They run from a checkout; none of them is in the wheel.

Each one reads its arguments before it reads or writes a file. `--help` (or `-h`) prints its usage and exits 0. Any other argument is a usage error, exit 2, except `--check` for the profile script. Neither one writes a file or runs a check.

## Fixture generator

[`generate-fixtures.mjs`](../scripts/generate-fixtures.mjs) is the deterministic fixture generator:

```bash
node scripts/generate-fixtures.mjs
```

It rewrites the fixtures and vectors it owns: every JSON file under `fixtures/` and `vectors/` except the two snapshot fixtures in [`fixtures/composition/hippo-rfc9421/`](../fixtures/composition/hippo-rfc9421/). It derives them from the RFC 8032 §7.1 seeds and the templates in the script. Then it writes `MANIFEST.sha256` from the JSON files under `fixtures/` and `vectors/` as it finds them. It self-checks that the composition signatures byte-match the pinned Envoys §14 vectors.

CI reruns the generator and then runs `git diff --exit-code` (the byte-pin step). So a committed fixture that differs from what the script writes for it fails CI. The two snapshot fixtures are pinned in `MANIFEST.sha256` but not regenerated: the generator pins them as found. So the byte-pin step fails when one of them changes without `MANIFEST.sha256`. It passes when the change is committed together with the refreshed `MANIFEST.sha256`.

## Conformance profile

[`conformance_profile.py`](../scripts/conformance_profile.py) writes `conformance.json`, the machine-readable profile derived from the fixtures. With `--check`, it checks that the committed file is current instead:

```bash
python3 scripts/conformance_profile.py
python3 scripts/conformance_profile.py --check
```

An option must be spelled in full: `--che` is a usage error, not taken for `--check`.

`--check` also fails when a document claims more than the fixtures show:

- A coverage claim in the top-level `README.md` or in `docs/coverage.md` names an envelope that `notCovered` still lists, unless the claim marks it "(unverified)".
- `README.md`, `docs/coverage.md` or `fixtures/composition/README.md` says the suite composes with an adjacent layer (wire signature, identity claims, delegation/continuity) that no fixture under `fixtures/composition/` carries a `spec` entry for. A `spec` entry of a composition fixture that is not a JSON object names no adjacent layer.
- The "at present" fixture count in the `COSIGNERS.md` baseline row differs from the number of fixtures.

### Fixtures the script cannot profile

In both modes, the script reports a fixture it cannot profile in one line that names the file, with exit code 1. That covers a fixture:

- that is not UTF-8 text;
- that Python's `json` module rejects with a syntax error;
- that holds `NaN`, `Infinity` or `-Infinity`, which that module reads as numbers unless told not to, and which are not valid JSON;
- that parses to a value other than a JSON object;
- that lacks a field the profile is derived from, or has one of another JSON type. Those fields are `name` and `description` (strings), `spec` (an array) and `expected` (an object). The line names every such field.

The same holds for a fixture that may be valid JSON but that the script cannot read, or whose requirement entry it cannot write. The line names the cause:

- nesting too deep for the `json` module of the running Python to parse, or to write in a value the entry is derived from. Those values are `name`, `description`, `spec`, and the `verifyResult` and `rejectCategory` of `expected`. The depth differs between Python versions; below it, the fixture is profiled;
- an integer of more digits than Python converts (4,300 by default);
- a number in such a value too large for a Python float, such as `1e400`;
- a lone surrogate in such a value, which UTF-8 cannot encode.

For the first three, the line says that this is a limit of the script, not a JSON error.

The script reads fixtures and documents and writes the profile as UTF-8, whatever the locale. Regeneration encodes the whole profile before it opens `conformance.json`. So a run that reports a fixture leaves the file as it was.

## Documentation path check

[`check-doc-links.mjs`](../scripts/check-doc-links.mjs) checks the paths that the tracked Markdown files point at. Run it from the repository root:

```bash
node scripts/check-doc-links.mjs
```

From another directory, adjust the script path, for example `node ../../scripts/check-doc-links.mjs` from `fixtures/levels/`. The result does not depend on the working directory. The check needs a git checkout: it reads the list of tracked Markdown files from `git ls-files`.

It fails when one of these does not resolve:

- a relative link in a tracked Markdown file;
- the script path of a `node` or `python3` command in one of its code blocks, including a command chained after `&&`, `||`, `;` or `|`.

It also fails when a file that a `cosign sign-blob` command writes is ignored by git in the `.sigstore/<org>/` directory the same code block says to commit it under.

In a code block, text from an unquoted `#` that starts a word is a comment. The command script paths and cosign output flags in it are not read; the `.sigstore/<org>/` directory is.

### Command script paths

A command script path may be relative to the Markdown file's directory or to the repository root. A `cd <dir>` or `cd -- <dir>` earlier on the same line moves it. A redirection on the `cd` is set aside in each of these forms:

- written as its own word, as in `cd fixtures 2>/dev/null`;
- written against the directory, as in `cd fixtures>/dev/null`;
- with a `<placeholder>` as its target, as in `cd fixtures 2><log>`.

A code block labelled as shell splits a line at parentheses. The labels are `bash`, `sh`, `zsh`, `ksh`, `shell`, `console`, `shell-session` and `sh-session`, in any letter case. In such a block, a `cd` inside a subshell, as in `(cd <dir> && node ...)`, applies up to the closing parenthesis.

Other blocks do not split at parentheses. In them, a `cd` that opens a subshell is one the check cannot resolve. Such a `cd` is `(cd <dir>` at the start of the line or after a blank, `=`, `$`, `<` or `>`, as in `$(cd <dir>` and `<(cd <dir>`. The commands from it to the parenthesis that closes the subshell are not checked. The commands before the subshell and after it are checked as if it were not there. Put such a line in a shell-labelled block to have the commands inside checked.

A `cd` the check cannot resolve skips the commands it would move. The check does not resolve a `cd` with:

- an option such as `-P`;
- a variable, `~` or `-`;
- a `<placeholder>` in the directory, such as `<your-clone>`;
- more than one operand;
- a path longer than 4096 characters.

Nor does it follow any `cd` past the 32nd on one line.

#!/usr/bin/env node
// Checks that every relative path a tracked Markdown file points at exists:
//   - inline links `[text](target)` and reference definitions `[ref]: target`,
//     resolved against the Markdown file's directory (`/`-rooted targets against the
//     repo root, as GitHub renders them);
//   - the script argument of each `node` / `python3` command inside fenced code
//     blocks, including commands chained after `&&`, `||`, `;` or `|`. The script
//     must exist relative to the Markdown file's directory or the repo root (the
//     two working directories a reader can be expected to run them from), moved
//     by any `cd <dir>` or `cd -- <dir>` earlier on the same line. A `cd` inside
//     a subshell, `(cd <dir> && node ...)`, moves only the commands up to the
//     closing parenthesis;
//   - the files a `cosign sign-blob` command writes, in a fenced code block that tells
//     the reader to commit them under `.sigstore/<org>/`, which must not be ignored by
//     git at that location (`<placeholder>` segments are checked as `example-org`).
// URLs with a scheme and same-page `#anchor` links are skipped.
//
// Exit codes: 0 = every path resolves, 1 = at least one does not, or the check
// could not run (one `error:` line names the cause).

import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, posix, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

// Link text and destination exclude `[` and `]`, so a match attempt never runs
// past the next bracket and a long line is scanned in linear time.
const INLINE_LINK = /\[[^[\]]*\]\(\s*<?([^)\s>[\]]+)>?(?:\s+"[^"]*")?\s*\)/g;
const REF_DEFINITION = /^\s{0,3}\[[^\]]+\]:\s*<?(\S+?)>?(?:\s|$)/;
// A command can start after `&&`, `;` or `|`, and after the `(` that opens a
// subshell or the `)` that closes one. The group keeps each boundary in the
// split, so the parentheses can be followed. `||` needs no alternative of its
// own: `|` splits it into an empty piece, which matches no command.
const COMMAND_BOUNDARY = /(&&|[;|()])/;
const SCRIPT_COMMAND = /^(?:\$\s+)?(?:node|python3?)\s+(\S+\.(?:mjs|cjs|js|py))(?:\s|$)/;
const CD_COMMAND = /^(?:\$\s+)?cd(?:\s+(.*))?$/s;
const FENCE = /^\s{0,3}(`{3,}|~{3,})/;
const SIGSTORE_DIR = /(?:^|[\s`'"(])(\.sigstore\/\S*?\/)(?=$|[\s`'")])/;
const COSIGN_SIGN = /^\s*(?:\$\s+)?cosign\s+sign-blob\s/;
const COSIGN_OUTPUT = /--(?:output-signature|output-certificate|bundle)(?:=|\s+)(\S+)/g;

// Joins `\`-continued shell lines so each entry is one whole command.
function commands(block) {
  const out = [];
  let current = null;
  for (const { text, where } of block) {
    if (current === null) current = { text: "", where };
    const continued = /\\\s*$/.test(text);
    current.text += `${continued ? text.replace(/\\\s*$/, "") : text} `;
    if (!continued) {
      out.push(current);
      current = null;
    }
  }
  if (current !== null) out.push(current);
  return out;
}

function checkCosignOutputs(block) {
  const broken = [];
  let checked = 0;
  const dirMatch = block.map(({ text }) => text.match(SIGSTORE_DIR)).find(Boolean);
  if (!dirMatch) return { checked, broken };
  const commitDir = dirMatch[1].replace(/<[^>]*>/g, "example-org");

  for (const cmd of commands(block)) {
    if (!COSIGN_SIGN.test(cmd.text)) continue;
    for (const [, output] of cmd.text.matchAll(COSIGN_OUTPUT)) {
      checked++;
      const target = posix.join(commitDir, posix.basename(output));
      const checkIgnore = (...flags) =>
        spawnSync("git", ["check-ignore", "--no-index", ...flags, "--", target], {
          cwd: ROOT,
          encoding: "utf8",
        });
      // Without -v the status reflects the final verdict; -v also exits 0 on a `!` re-include.
      const result = checkIgnore("-q");
      if (result.status === 0) {
        const rule = checkIgnore("-v").stdout.split("\t")[0].trim();
        broken.push(`${cmd.where}  cosign output ${output} -> ${target} is ignored by git (${rule})`);
      } else if (result.status !== 1) {
        broken.push(`${cmd.where}  cosign output ${output} -> ${target} (git check-ignore failed: ${result.stderr.trim()})`);
      }
    }
  }
  return { checked, broken };
}

function trackedMarkdown() {
  try {
    const out = execFileSync("git", ["ls-files", "-z", "--", "*.md"], {
      cwd: ROOT,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    return out.split("\0").filter(Boolean);
  } catch (err) {
    const cause =
      err.code === "ENOENT" ? "git is not installed" : String(err.stderr ?? "").trim().split("\n")[0] || err.message;
    console.error(
      `error: git ls-files failed in ${ROOT} (${cause}); the check reads the list of tracked Markdown files from git, so run it in a git checkout`,
    );
    process.exit(1);
  }
}

function isExternal(target) {
  return /^[a-z][a-z0-9+.-]*:/i.test(target) || target.startsWith("#");
}

// Returns the decoded path, or null when the target's percent-encoding is
// malformed (a `%` not followed by two hex digits).
function stripSuffix(target) {
  try {
    return decodeURIComponent(target.replace(/[?#].*$/, ""));
  } catch (err) {
    if (err instanceof URIError) return null;
    throw err;
  }
}

function describeBase(base) {
  return base === ROOT ? "the repo root" : `${relative(ROOT, base)}/`;
}

// The directory a `cd` moves to (`cd <dir>`, `cd -- <dir>`), or null when this
// check cannot resolve it: no operand or more than one, an option other than a
// leading `--`, or a target that needs the shell (`cd`, `cd ~`, `cd "$DIR"`,
// `cd -`, `cd -P <dir>`).
function cdTarget(args = "") {
  const operands = args.split(/\s+/).filter(Boolean);
  if (operands[0] === "--") operands.shift();
  return operands.length === 1 && !/^[~-]|[$"'`]/.test(operands[0]) ? operands[0] : null;
}

function checkFile(relPath) {
  const abs = join(ROOT, relPath);
  const dir = dirname(abs);
  const broken = [];
  let checked = 0;
  let fence = null;
  let block = [];

  readFileSync(abs, "utf8")
    .split("\n")
    .forEach((line, i) => {
      const where = `${relPath}:${i + 1}`;
      const fenceMatch = line.match(FENCE);
      if (fenceMatch) {
        const marker = fenceMatch[1];
        if (fence === null) {
          fence = marker;
          block = [];
        } else if (marker[0] === fence[0] && marker.length >= fence.length) {
          fence = null;
          const result = checkCosignOutputs(block);
          checked += result.checked;
          broken.push(...result.broken);
        }
        return;
      }

      if (fence !== null) {
        block.push({ text: line, where });
        let bases = [...new Set([dir, ROOT])];
        // The bases to return to as each open subshell closes: a `cd` inside
        // `( ... )` or `$( ... )` moves the commands up to the closing `)` only.
        const outer = [];
        for (const piece of line.split(COMMAND_BOUNDARY)) {
          if (piece === "(") {
            outer.push(bases);
            continue;
          }
          if (piece === ")") {
            if (outer.length > 0) bases = outer.pop();
            continue;
          }
          const part = piece.trim();
          const cd = part.match(CD_COMMAND);
          if (cd) {
            // A target this check cannot resolve ends the checks for the rest of
            // the line, or of the subshell it is in, instead of guessing.
            const target = cdTarget(cd[1]);
            bases = target === null ? [] : [...new Set(bases.map((b) => resolve(b, target)))];
            continue;
          }
          const cmd = part.match(SCRIPT_COMMAND);
          if (!cmd || bases.length === 0) continue;
          checked++;
          const script = cmd[1];
          if (!bases.some((base) => existsSync(resolve(base, script)))) {
            broken.push(`${where}  command script ${script} (not found from ${bases.map(describeBase).join(" or ")})`);
          }
        }
        return;
      }

      const targets = [...line.matchAll(INLINE_LINK)].map((m) => m[1]);
      const ref = line.match(REF_DEFINITION);
      if (ref) targets.push(ref[1]);
      for (const target of targets) {
        if (isExternal(target)) continue;
        const path = stripSuffix(target);
        if (path === null) {
          checked++;
          broken.push(`${where}  link ${target} (malformed percent-encoding; write a literal % as %25)`);
          continue;
        }
        if (!path) continue;
        checked++;
        const resolved = path.startsWith("/") ? join(ROOT, path) : resolve(dir, path);
        if (!existsSync(resolved)) {
          broken.push(`${where}  link ${target} -> ${relative(ROOT, resolved)} (not found)`);
        }
      }
    });

  return { checked, broken };
}

let checked = 0;
const broken = [];
for (const file of trackedMarkdown()) {
  const result = checkFile(file);
  checked += result.checked;
  broken.push(...result.broken);
}

for (const line of broken) console.log(`FAIL  ${line}`);
console.log(`summary: ${checked} paths checked, ${broken.length} broken`);
process.exit(broken.length === 0 ? 0 : 1);

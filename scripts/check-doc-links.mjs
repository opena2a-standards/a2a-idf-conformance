#!/usr/bin/env node
// Checks that every relative path a tracked Markdown file points at exists:
//   - inline links `[text](target)` and reference definitions `[ref]: target`,
//     resolved against the Markdown file's directory (`/`-rooted targets against the
//     repo root, as GitHub renders them);
//   - the script argument of each `node` / `python3` command inside fenced code
//     blocks, including commands chained after `&&`, `||`, `;` or `|`. The script
//     must exist relative to the Markdown file's directory or the repo root (the
//     two working directories a reader can be expected to run them from), moved
//     by any `cd <dir>` or `cd -- <dir>` earlier on the same line. In a block
//     labelled as shell (`bash`, `sh`, ...), a `cd` inside a subshell,
//     `(cd <dir> && node ...)`, moves only the commands up to the closing
//     parenthesis; other blocks do not split at parentheses, so there a `cd`
//     that opens a subshell is one this check cannot resolve: the commands
//     from it to the closing parenthesis are not checked, those before the
//     subshell and after it are;
//   - the files a `cosign sign-blob` command writes, in a fenced code block that tells
//     the reader to commit them under `.sigstore/<org>/`, which must not be ignored by
//     git at that location (`<placeholder>` segments are checked as `example-org`).
// In a code block, text from an unquoted `#` that starts a word is a comment:
// the commands and cosign output flags in it are not read, the `.sigstore/<org>/`
// directory is. URLs with a scheme and same-page `#anchor` links are skipped.
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
// A command can start after `&&`, `;` or `|`. `||` needs no alternative of its
// own: `|` splits it into an empty piece, which matches no command.
const COMMAND_BOUNDARY = /&&|[;|]/;
// In a shell block a command can also start after the `(` that opens a subshell
// or the `)` that closes one. The group keeps each boundary in the split, so the
// parentheses can be followed.
const SHELL_COMMAND_BOUNDARY = /(&&|[;|()])/;
const SHELL_LANGUAGES = new Set(["bash", "sh", "zsh", "ksh", "shell", "console", "shell-session", "sh-session"]);
const SCRIPT_COMMAND = /^(?:\$\s+)?(?:node|python3?)\s+(\S+\.(?:mjs|cjs|js|py))(?:\s|$)/;
const CD_COMMAND = /^(?:\$\s+)?cd(?:\s+(.*))?$/s;
// A `(` that opens a subshell starting with `cd`: at the start of the line or
// after a blank, `=`, `$`, `<` or `>`, as in `(cd <dir>`, `X=(cd <dir>`,
// `$(cd <dir>`, `<(cd <dir>` and `>(cd <dir>`. Tried at one `(` at a time.
const SUBSHELL_OPENER = /[\s=$<>]/;
const SUBSHELL_CD = /\(\s*cd(?:\s|$)/y;
// A redirection word: `2>/dev/null`, `>>log`, `&>out`, `2>&1`, `<in`. With
// nothing after the operator, the next word is its target.
const REDIRECT = /^(?:\d+|&)?(?:<<<|<<-?|<>|<&|>&|>>|>\||<|>)(.*)$/;
// A `<name>` placeholder the reader fills in, as in `cd <your-clone>`: anywhere
// in a word, and at one position of it.
const PLACEHOLDER = /<[A-Za-z][^<>\s]*>/;
const PLACEHOLDER_HERE = new RegExp(PLACEHOLDER, "y");
// Bounds the work on one line, which otherwise grows with the square of its
// length: a `cd` past the 32nd on a line, or one that leads to a path longer
// than 4096 characters (PATH_MAX on Linux), is not followed.
const MAX_CD_STEPS = 32;
const MAX_DIRECTORY_LENGTH = 4096;
const FENCE = /^\s{0,3}(`{3,}|~{3,})/;
const COSIGN_SIGN = /^\s*(?:\$\s+)?cosign\s+sign-blob\s/;
const COSIGN_OUTPUT = /--(?:output-signature|output-certificate|bundle)(?:=|\s+)(\S+)/g;

const SIGSTORE_PREFIX = ".sigstore/";
const WORD_OPENERS = "`'\"(";
const WORD_CLOSERS = "`'\")";

// The `.sigstore/<dir>/` path a line names: it starts a word (or follows a quote,
// backtick or opening parenthesis) and runs to the first `/` that ends the word
// (or precedes a quote, backtick or closing parenthesis). Each word is scanned
// once. Only its first candidate start is tried: a later start in the same word
// could only end at a `/` the first one would have ended at too. A single
// pattern for this retries every start against the rest of the word, which is
// quadratic on a long line.
function sigstoreDir(line) {
  for (const word of line.split(/\s+/)) {
    let start = word.indexOf(SIGSTORE_PREFIX);
    while (start > 0 && !WORD_OPENERS.includes(word[start - 1])) {
      start = word.indexOf(SIGSTORE_PREFIX, start + 1);
    }
    if (start < 0) continue;
    let end = word.indexOf("/", start + SIGSTORE_PREFIX.length);
    while (end >= 0 && end + 1 < word.length && !WORD_CLOSERS.includes(word[end + 1])) {
      end = word.indexOf("/", end + 1);
    }
    if (end >= 0) return word.slice(start, end + 1);
  }
  return null;
}

// Replaces each `<placeholder>` with `example-org`, in one pass.
function fillPlaceholders(path) {
  let out = "";
  let from = 0;
  for (;;) {
    const open = path.indexOf("<", from);
    const close = open < 0 ? -1 : path.indexOf(">", open + 1);
    if (close < 0) return out + path.slice(from);
    out += `${path.slice(from, open)}example-org`;
    from = close + 1;
  }
}

// Joins `\`-continued shell lines so each entry is one whole command, without
// the comment of any line.
function commands(block) {
  const out = [];
  let current = null;
  for (const { text: line, where } of block) {
    const text = stripComment(line);
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
  const dir = block.map(({ text }) => sigstoreDir(text)).find(Boolean);
  if (!dir) return { checked, broken };
  const commitDir = fillPlaceholders(dir);

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

// The line up to an unquoted `#` that starts a word, where the shell's comment
// begins. One pass over the line.
function stripComment(line) {
  let quote = null;
  // A word starts at the start of the line and after an unquoted, unescaped
  // blank or operator character. An escaped one, as in `\ #`, is part of a word.
  let wordStart = true;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (quote !== null) {
      if (c === quote) quote = null;
      else if (c === "\\" && quote === '"') i++;
    } else if (c === "\\") {
      i++;
    } else if (c === "'" || c === '"') {
      quote = c;
    } else if (c === "#" && wordStart) {
      return line.slice(0, i);
    } else {
      wordStart = /[\s;&|()<>]/.test(c);
      continue;
    }
    wordStart = false;
  }
  return line;
}

// The line of a block that is not split at parentheses, with each subshell that
// starts with `cd` replaced by a blank, from its `(` to the `)` that closes it
// (or to the end of the line). Where the `cd` leads is not followed there, so
// the commands inside are not checked; the commands before the subshell and
// after it are not moved by its `cd`, and are. Parentheses are counted as
// written, quoted or not, as a shell block splits at them. One pass.
function withoutCdSubshells(line) {
  let out = "";
  let from = 0;
  let depth = 0;
  for (let i = 0; i < line.length; i++) {
    if (line[i] === "(") {
      if (depth > 0) {
        depth++;
      } else if (i === 0 || SUBSHELL_OPENER.test(line[i - 1])) {
        SUBSHELL_CD.lastIndex = i;
        if (!SUBSHELL_CD.test(line)) continue;
        out += `${line.slice(from, i)} `;
        depth = 1;
      }
    } else if (line[i] === ")" && depth > 0 && --depth === 0) {
      from = i + 1;
    }
  }
  return depth > 0 ? out : out + line.slice(from);
}

// Where the first redirection starts in a word of a `cd` command, or -1: 0 for
// a word of its own (`2>/dev/null`), the end of the operand for one written
// against it (`fixtures>/dev/null`, `fixtures&>/dev/null`). A `<` that opens a
// `<placeholder>` is not an operator: `fixtures/<level>` has no redirection,
// and `2><log>` is one whose target is the placeholder.
function redirectionStart(word) {
  const operator = /&?[<>]/g;
  for (let first = true, match; (match = operator.exec(word)) !== null; first = false) {
    const bracket = operator.lastIndex - 1;
    PLACEHOLDER_HERE.lastIndex = bracket;
    const placeholder = PLACEHOLDER_HERE.exec(word);
    if (placeholder === null) return first && REDIRECT.test(word) ? 0 : match.index;
    operator.lastIndex = bracket + placeholder[0].length;
  }
  return -1;
}

// The directory a `cd` moves to (`cd <dir>`, `cd -- <dir>`, with any
// redirections such as `2>/dev/null` set aside), or null when this check cannot
// resolve it: no operand or more than one, an option other than a leading `--`,
// a `<placeholder>` in the directory, or a target that needs the shell (`cd`,
// `cd ~`, `cd "$DIR"`, `cd -`, `cd -P <dir>`).
function cdTarget(args = "") {
  const words = args.split(/\s+/).filter(Boolean);
  const operands = [];
  for (let i = 0; i < words.length; i++) {
    const word = words[i];
    const at = redirectionStart(word);
    const operand = at < 0 ? word : word.slice(0, at);
    // The placeholder rule is for the directory: a redirection target can be one.
    if (PLACEHOLDER.test(operand)) return null;
    if (at !== 0) operands.push(operand);
    if (at >= 0 && word.slice(at).match(REDIRECT)[1] === "" && ++i === words.length) return null;
  }
  if (operands[0] === "--") operands.shift();
  return operands.length === 1 && !/^[~-]|[$"'`]/.test(operands[0]) ? operands[0] : null;
}

function checkFile(relPath) {
  const abs = join(ROOT, relPath);
  const dir = dirname(abs);
  const broken = [];
  let checked = 0;
  let fence = null;
  let shell = false;
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
          const language = line.slice(fenceMatch[0].length).trim().split(/\s/)[0].toLowerCase();
          shell = SHELL_LANGUAGES.has(language);
          block = [];
        } else if (marker[0] === fence[0] && marker.length >= fence.length) {
          fence = null;
          const result = checkCosignOutputs(block);
          checked += result.checked;
          for (const entry of result.broken) broken.push(entry);
        }
        return;
      }

      if (fence !== null) {
        block.push({ text: line, where });
        let bases = [...new Set([dir, ROOT])];
        // The bases to return to as each open subshell closes: a `cd` inside
        // `( ... )` or `$( ... )` moves the commands up to the closing `)` only.
        const outer = [];
        let cdSteps = 0;
        const command = stripComment(line);
        // Outside a shell block the parentheses stay in the piece, so a `cd`
        // that opens a subshell is not followed: the subshell is set aside.
        const pieces = shell ? command.split(SHELL_COMMAND_BOUNDARY) : withoutCdSubshells(command).split(COMMAND_BOUNDARY);
        for (const piece of pieces) {
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
            // A target this check cannot resolve, or one past the bounds, ends
            // the checks for the rest of the line, or of the subshell it is in,
            // instead of guessing.
            const target = ++cdSteps > MAX_CD_STEPS ? null : cdTarget(cd[1]);
            bases =
              target === null || bases.length === 0
                ? []
                : [...new Set(bases.map((b) => resolve(b, target)))].filter((b) => b.length <= MAX_DIRECTORY_LENGTH);
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
  // One push per entry: spreading a long list into one call overflows the stack.
  for (const entry of result.broken) broken.push(entry);
}

for (const line of broken) console.log(`FAIL  ${line}`);
console.log(`summary: ${checked} paths checked, ${broken.length} broken`);
// Not process.exit(), which can end the process before output written to a pipe
// is flushed.
process.exitCode = broken.length === 0 ? 0 : 1;

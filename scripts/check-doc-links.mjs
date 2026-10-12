#!/usr/bin/env node
// Checks that every relative path a tracked Markdown file points at exists:
//   - inline links `[text](target)` and reference definitions `[ref]: target`,
//     resolved against the Markdown file's directory (`/`-rooted targets against the
//     repo root, as GitHub renders them);
//   - the script argument of `node` / `python3` commands inside fenced code blocks,
//     which must exist relative to the Markdown file's directory or the repo root
//     (the two working directories a reader can be expected to run them from);
//   - the files a `cosign sign-blob` command writes, in a fenced code block that tells
//     the reader to commit them under `.sigstore/<org>/`, which must not be ignored by
//     git at that location (`<placeholder>` segments are checked as `example-org`).
// URLs with a scheme and same-page `#anchor` links are skipped.
//
// Exit codes: 0 = every path resolves, 1 = at least one does not.

import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, posix, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const INLINE_LINK = /\[[^\]]*\]\(\s*<?([^)\s>]+)>?(?:\s+"[^"]*")?\s*\)/g;
const REF_DEFINITION = /^\s{0,3}\[[^\]]+\]:\s*<?(\S+?)>?(?:\s|$)/;
const SCRIPT_COMMAND = /^\s*(?:\$\s+)?(?:node|python3?)\s+(\S+\.(?:mjs|cjs|js|py))(?:\s|$)/;
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
  const out = execFileSync("git", ["ls-files", "-z", "--", "*.md"], {
    cwd: ROOT,
    encoding: "utf8",
  });
  return out.split("\0").filter(Boolean);
}

function isExternal(target) {
  return /^[a-z][a-z0-9+.-]*:/i.test(target) || target.startsWith("#");
}

function stripSuffix(target) {
  return decodeURIComponent(target.replace(/[?#].*$/, ""));
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
        const cmd = line.match(SCRIPT_COMMAND);
        if (!cmd) return;
        checked++;
        const script = cmd[1];
        if (!existsSync(resolve(dir, script)) && !existsSync(resolve(ROOT, script))) {
          broken.push(`${where}  command script ${script} (not found from ${relative(ROOT, dir) || "."}/ or the repo root)`);
        }
        return;
      }

      const targets = [...line.matchAll(INLINE_LINK)].map((m) => m[1]);
      const ref = line.match(REF_DEFINITION);
      if (ref) targets.push(ref[1]);
      for (const target of targets) {
        if (isExternal(target)) continue;
        const path = stripSuffix(target);
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

#!/usr/bin/env node
// Reads the live `status:` field from the ERC-8004 frontmatter in ethereum/ERCs and
// compares it to the value this repo last recorded. The erc-8004-bridge fixture set
// (issue #5) is parked on that field leaving `Draft`; the point of this script is that
// nobody has to remember to look.
//
// Exit codes: 0 = unchanged, 10 = status changed, 1 = could not read upstream.

import { readFileSync, writeFileSync } from "node:fs";

const SPEC_URL =
  "https://raw.githubusercontent.com/ethereum/ERCs/master/ERCS/erc-8004.md";
const PINNED = ".github/erc-8004-upstream.json";

function parseFrontmatterStatus(text) {
  // Frontmatter is the first `---` delimited block. Do not regex the whole document:
  // `status:` also appears in prose, and a body match would silently report the wrong
  // field.
  if (!text.startsWith("---")) throw new Error("no frontmatter delimiter at byte 0");
  const end = text.indexOf("\n---", 3);
  if (end === -1) throw new Error("unterminated frontmatter");
  const block = text.slice(3, end);
  const line = block
    .split("\n")
    .find((l) => /^status:\s*\S/.test(l));
  if (!line) throw new Error("no status field in frontmatter");
  return line.replace(/^status:\s*/, "").trim();
}

const res = await fetch(SPEC_URL);
if (!res.ok) {
  console.error(`FAIL  could not fetch ${SPEC_URL}: HTTP ${res.status}`);
  process.exit(1);
}
const observed = parseFrontmatterStatus(await res.text());

const pinned = JSON.parse(readFileSync(PINNED, "utf8"));
const expected = pinned.status;

console.log(`upstream : ${observed}`);
console.log(`recorded : ${expected}`);

if (observed === expected) {
  console.log(`unchanged. The erc-8004-bridge fixture set stays parked (issue #5).`);
  process.exit(0);
}

console.log(
  `CHANGED. ERC-8004 moved from ${expected} to ${observed}. ` +
    `Revisit fixtures/composition/README.md and issue #5.`
);
if (process.env.WRITE_BACK === "1") {
  pinned.status = observed;
  pinned.observedAt = new Date().toISOString().slice(0, 10);
  writeFileSync(PINNED, JSON.stringify(pinned, null, 2) + "\n");
}
process.exit(10);

"""Build hook: the package description is README.md with its links made absolute.

`pyproject.toml` lists `readme` under `project.dynamic` and names this file as
hatchling's custom metadata hook, so hatchling calls :meth:`ReadmeHook.update`
whenever it builds the package, as `pipx run` and `pip` do. The hook sets the
description to the text of `README.md` with each relative link rewritten to
the file on GitHub under `project.urls.Repository`: `blob/main/<path>` for a
file, `tree/main/<path>` for a directory, with the fragment kept.

`README.md` itself keeps its relative links: GitHub resolves them against the
branch a reader is on, and `scripts/check-doc-links.mjs` checks that each one
resolves in the checkout. PyPI renders a description with `readme_renderer`,
which leaves a relative link as it is, so on the project page
`./docs/coverage.md` would point under pypi.org, where there is no such page.

A link inside a fenced code block is code, not a link, and is not rewritten.
A link whose path is not in the checkout is rewritten to `blob/main/<path>`
all the same: the hook fails no build over a link, and
`scripts/parity/test_entry_point.py` checks that every rewritten path exists.
An image written as `![alt](./path)` is rewritten the same way, to the file's
page on GitHub, not to its bytes; `README.md` has none.
"""
from __future__ import annotations

import re
from pathlib import Path

try:
    from hatchling.metadata.plugin.interface import MetadataHookInterface
except ModuleNotFoundError:  # outside a build, where the tests import absolute_links()
    MetadataHookInterface = object

BRANCH = "main"
README = "README.md"

# `[text](target)`, `[text](<target>)` and `[text](target "title")`: the
# INLINE_LINK pattern of scripts/check-doc-links.mjs, with the text before and
# after the target captured so that the target alone is replaced.
INLINE_LINK = re.compile(r'(\[[^\[\]]*\]\(\s*<?)([^)\s>\[\]]+)(>?(?:\s+"[^"]*")?\s*\))')
# The FENCE pattern of scripts/check-doc-links.mjs: a line opening or closing a
# fenced code block.
FENCE = re.compile(r"^\s{0,3}(`{3,}|~{3,})")
# A target with a URL scheme (`https:`, `mailto:`) is absolute already.
SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*:", re.IGNORECASE)


def is_relative(target: str) -> bool:
    """True for a link target that names a path in the repository: no URL
    scheme, and not a fragment of the same page."""
    return not SCHEME.match(target) and not target.startswith("#")


def absolute_target(target: str, root: Path, repository: str) -> str:
    """`./docs/coverage.md#status` -> `<repository>/blob/main/docs/coverage.md#status`,
    `./vectors/` -> `<repository>/tree/main/vectors/`."""
    path, hash_sign, fragment = target.partition("#")
    if path.startswith("./"):
        path = path[2:]
    kind = "tree" if (root / path).is_dir() else "blob"
    return f"{repository.rstrip('/')}/{kind}/{BRANCH}/{path}{hash_sign}{fragment}"


def absolute_links(markdown: str, root: Path, repository: str) -> str:
    """`markdown` with each relative link outside a fenced code block rewritten
    by :func:`absolute_target`."""

    def rewrite(match: re.Match) -> str:
        before, target, after = match.groups()
        if is_relative(target):
            target = absolute_target(target, root, repository)
        return before + target + after

    lines = []
    fence = None
    for line in markdown.split("\n"):
        opened = FENCE.match(line)
        if opened:
            marker = opened.group(1)
            if fence is None:
                fence = marker
            elif marker[0] == fence[0] and len(marker) >= len(fence):
                fence = None
            lines.append(line)
            continue
        lines.append(line if fence is not None else INLINE_LINK.sub(rewrite, line))
    return "\n".join(lines)


class ReadmeHook(MetadataHookInterface):
    """Sets `readme` to README.md with absolute links; see the module docstring."""

    def update(self, metadata: dict) -> None:
        repository = metadata.get("urls", {}).get("Repository")
        if not isinstance(repository, str) or not repository:
            raise ValueError(
                "project.urls.Repository is not set in pyproject.toml; the readme hook "
                "rewrites the README's relative links to that repository"
            )
        root = Path(self.root)
        text = (root / README).read_text(encoding="utf-8")
        metadata["readme"] = {
            "content-type": "text/markdown",
            "text": absolute_links(text, root, repository),
        }

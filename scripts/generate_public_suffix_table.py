#!/usr/bin/env python3
"""Generate the compiled-in curated public-suffix table.

The application never fetches the PSL at runtime. Maintainers update
scripts/public_suffixes.txt from the official snapshot, then run this script
from the repository root. The output is deterministic and checked in.
"""

from __future__ import annotations

import argparse
from pathlib import Path


def parse_rules(source: Path) -> tuple[str, str, list[str], list[str], list[str]]:
    snapshot = ""
    commit = ""
    exact: set[str] = set()
    wildcard: set[str] = set()
    exception: set[str] = set()

    for raw_line in source.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("# snapshot:"):
            snapshot = line.partition(":")[2].strip()
            continue
        if line.startswith("# commit:"):
            commit = line.partition(":")[2].strip()
            continue
        if line.startswith("#"):
            continue

        rule = line.lower()
        if any(ord(char) > 0x7F for char in rule):
            raise ValueError(f"non-ASCII rule must be punycode encoded: {line}")
        if rule.startswith("!."):
            raise ValueError(f"invalid exception rule: {line}")
        if rule.startswith("!"):
            exception.add(rule[1:])
        elif rule.startswith("*."):
            wildcard.add(rule[2:])
        else:
            exact.add(rule)

    if not snapshot or not commit:
        raise ValueError("source must declare '# snapshot:' and '# commit:'")

    overlap = (exact & wildcard) | (exact & exception) | (wildcard & exception)
    if overlap:
        raise ValueError(f"rules occur in multiple categories: {sorted(overlap)}")

    return snapshot, commit, sorted(exact), sorted(wildcard), sorted(exception)


def format_array(name: str, rules: list[str], doc: str) -> str:
    values = "\n".join(f'    "{rule}",' for rule in rules)
    return (
        f"{doc}\n"
        f"inline constexpr std::array<std::string_view, {len(rules)}> {name} = {{{{\n"
        f"{values}\n"
        "}};\n"
    )


def generate(source: Path, destination: Path) -> None:
    snapshot, commit, exact, wildcard, exception = parse_rules(source)
    text = f"""#pragma once

/**
 * @brief Compiled-in curated public-suffix rules for registrable-domain tests.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Utilities
 *
 * GENERATED FILE. scripts/generate_public_suffix_table.py writes it from
 * scripts/public_suffixes.txt. A hand edit is lost on the next run of the
 * generator. To change a rule, edit the rule source; to change the prose or
 * the layout, edit the generator template.
 *
 * The table is a curated subset of the Mozilla Public Suffix List, not the
 * whole list. seal never fetches the list at run time, so this snapshot is the
 * only rule source that seal::url::detail::publicSuffixView() reads.
 *
 * The rules are split by match kind, because each kind is applied differently:
 *  - @ref kExactPublicSuffixes - the rule is itself a public suffix. The
 *    longest dot-aligned match, counted in labels, wins.
 *  - @ref kWildcardPublicSuffixes - the base of a `*.<base>` rule. A match
 *    consumes exactly one more label to the left of the base.
 *  - @ref kPublicSuffixExceptions - the body of a `!<rule>` line. An exception
 *    outranks both other kinds, and the public suffix it yields is the rule
 *    without its left-most label.
 *
 * A host that matches no rule falls back to its last label. That is the
 * implicit `*` rule of the PSL algorithm.
 *
 * Every array is sorted, lower-case and ASCII; the generator rejects a rule
 * that is not punycode-encoded. Lookup scans the three arrays linearly.
 */

#include <array>
#include <string_view>

namespace seal::url::detail
{{

/// Snapshot identity of the curated list, as `YYYY-MM-DD_HH-MM-SS_UTC`.
inline constexpr std::string_view kSuffixTableSnapshot = "{snapshot}";

/// Upstream PSL commit that the curated snapshot was reviewed against.
inline constexpr std::string_view kSuffixTableCommit = "{commit}";

{format_array("kExactPublicSuffixes", exact, "/// Rules that are themselves public suffixes.")}
{format_array("kWildcardPublicSuffixes", wildcard, "/// Bases of `*.<base>` rules; a match takes one more label.")}
{format_array("kPublicSuffixExceptions", exception, "/// Bodies of `!<rule>` lines; each one cancels a wildcard match.")}
}}  // namespace seal::url::detail
"""
    destination.write_text(text, encoding="utf-8", newline="\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--source",
        type=Path,
        default=Path("scripts/public_suffixes.txt"),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("src/PublicSuffixTable.hpp"),
    )
    args = parser.parse_args()
    generate(args.source, args.output)


if __name__ == "__main__":
    main()

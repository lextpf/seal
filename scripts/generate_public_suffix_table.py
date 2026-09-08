#!/usr/bin/env python3
"""
@brief generate the deterministic public-suffix header.

maintainers update scripts/public_suffixes.txt from a PSL snapshot, then run
this script from the repository root. the application performs no runtime fetch.
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
 * @brief curated public-suffix rules for registrable-domain checks.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Utilities
 *
 * generated from scripts/public_suffixes.txt; edit that file or the generator template.
 * this PSL subset is the sole runtime rule source. arrays are sorted, lowercase ASCII.
 *
 * | kind      | matching rule                                      |
 * |-----------|----------------------------------------------------|
 * | exact     | longest dot-aligned suffix wins                    |
 * | wildcard  | consume one label before the stored base           |
 * | exception | override other rules; remove the leftmost label    |
 * | no match  | use the final host label (implicit wildcard)       |
 */

#include <array>
#include <string_view>

namespace seal::url::detail
{{

/// snapshot time as YYYY-MM-DD_HH-MM-SS_UTC.
inline constexpr std::string_view kSuffixTableSnapshot = "{snapshot}";

/// upstream PSL commit used to review this subset.
inline constexpr std::string_view kSuffixTableCommit = "{commit}";

{format_array("kExactPublicSuffixes", exact, "/// exact suffix rules.")}
{format_array("kWildcardPublicSuffixes", wildcard, "/// wildcard bases; consume one extra label.")}
{format_array("kPublicSuffixExceptions", exception, "/// exception bodies; override exact and wildcard matches.")}
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

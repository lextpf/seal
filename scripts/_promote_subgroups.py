"""Promote nested subgroup docs to top-level directories.

Doxide generates top-level directories for C++ namespaces but not for
classes.  When a project uses classes instead of namespaces, subgroup
pages only exist nested under their parent group (e.g.,
Core/ArchiveService/).  clean_docs.py rewrites subgroup links with ../
to point to top-level directories.  This script bridges the gap by
copying nested subgroup directories to the top level so the links
resolve correctly.

When a subgroup directory contains a class page matching the subgroup
name (e.g., ArchiveService/ArchiveService.md), the class content
replaces the stub index.md so users land directly on the full
documentation instead of an intermediate page.

Reads doxide.yml to discover the group hierarchy, then for each
subgroup copies ParentGroup/SubGroup/ -> SubGroup/ if the top-level
directory does not already exist.

No external dependencies — uses only the Python standard library.

Usage:
    python scripts/promote_subgroups.py          # defaults to docs/
    python scripts/promote_subgroups.py path/    # custom docs directory
"""

import re
import shutil
import sys
from pathlib import Path


def parse_group_hierarchy(config_path: Path) -> list[tuple[str, str]]:
    """Parse doxide.yml and return (parent, child) name pairs.

    Uses a simple indent-aware line parser instead of PyYAML so the
    script has zero external dependencies.
    """
    text = config_path.read_text(encoding="utf-8")
    pairs = []
    parent_name = ""
    in_child_groups = False

    for line in text.split("\n"):
        stripped = line.rstrip()
        indent = len(line) - len(line.lstrip())

        # Top-level group: "  - name: Core" (indent 2-4)
        m = re.match(r"^  - name:\s+(.+)", stripped)
        if m:
            parent_name = m.group(1).strip()
            in_child_groups = False
            continue

        # Child groups key: "    groups:" (indent 4-6)
        if re.match(r"^\s{4,6}groups:\s*$", stripped):
            in_child_groups = True
            continue

        # Child group entry: "      - name: Logger" (indent 6+)
        if in_child_groups and indent >= 6:
            m = re.match(r"^\s+- name:\s+(.+)", stripped)
            if m:
                pairs.append((parent_name, m.group(1).strip()))
                continue

        # Any non-indented or top-level key resets child context
        if indent < 4 and stripped and not stripped.startswith("#"):
            in_child_groups = False

    return pairs


def promote_class_to_index(top_level: Path, child_name: str) -> None:
    """Replace stub index.md with the class page content if it exists.

    Doxide generates a stub index.md (just title + Types table) and a
    separate ClassName.md with the full documentation.  This merges
    the class content into index.md and removes the redundant file.
    """
    class_page = top_level / f"{child_name}.md"
    index_page = top_level / "index.md"

    if not class_page.exists():
        return

    content = class_page.read_text(encoding="utf-8")
    index_page.write_text(content, encoding="utf-8")
    class_page.unlink()


def main():
    docs_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("docs")
    config_path = Path("doxide.yml")

    if not config_path.exists():
        print("error: doxide.yml not found", file=sys.stderr)
        sys.exit(1)
    if not docs_dir.is_dir():
        print(f"error: {docs_dir} is not a directory", file=sys.stderr)
        sys.exit(1)

    pairs = parse_group_hierarchy(config_path)
    promoted = 0

    for parent_name, child_name in pairs:
        nested = docs_dir / parent_name / child_name
        top_level = docs_dir / child_name

        if nested.is_dir() and not top_level.exists():
            shutil.copytree(nested, top_level)
            promote_class_to_index(top_level, child_name)
            promoted += 1
            print(f"  {parent_name}/{child_name}/ -> {child_name}/")

    print(f"done: {promoted} subgroup(s) promoted")


if __name__ == "__main__":
    main()

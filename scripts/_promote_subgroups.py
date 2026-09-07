"""
@brief copy nested subgroup pages to the paths used by _clean_docs.py.

read the hierarchy from doxide.yml. copy only missing top-level directories;
a matching class page replaces the copied index. run before _clean_docs.py.
the optional argument selects the docs directory (default: docs).
"""

import re
import shutil
import sys
from pathlib import Path


def parse_group_hierarchy(config_path: Path) -> list[tuple[str, str]]:
    """
    @brief read parent/child group pairs using the config indentation.

    this parser supports the doxide.yml layout without a YAML dependency.
    """
    text = config_path.read_text(encoding="utf-8")
    pairs = []
    parent_name = ""
    in_child_groups = False

    for line in text.split("\n"):
        stripped = line.rstrip()
        indent = len(line) - len(line.lstrip())


        m = re.match(r"^  - name:\s+(.+)", stripped)
        if m:
            parent_name = m.group(1).strip()
            in_child_groups = False
            continue


        if re.match(r"^\s{4,6}groups:\s*$", stripped):
            in_child_groups = True
            continue


        if in_child_groups and indent >= 6:
            m = re.match(r"^\s+- name:\s+(.+)", stripped)
            if m:
                pairs.append((parent_name, m.group(1).strip()))
                continue


        if indent < 4 and stripped and not stripped.startswith("#"):
            in_child_groups = False

    return pairs


def promote_class_to_index(top_level: Path, child_name: str) -> None:
    """
    @brief replace the index with a matching class page and delete that page.

    leave the index unchanged if no class page exists.
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

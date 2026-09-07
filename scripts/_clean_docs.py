"""
@brief prepare generated Markdown for MkDocs.

edit only pages with doxide frontmatter. run after _promote_subgroups.py;
the optional argument selects the docs directory (default: docs).
"""

import re
import sys
from pathlib import Path


def is_doxide_generated(text: str) -> bool:
    return "generator: doxide" in text[:200]


def fix_admonition_indent(text: str) -> str:
    """
    @brief expand doxide admonition bodies to the four-space indent required by MkDocs.
    """
    lines = text.split("\n")
    result = []
    in_admonition = False

    for line in lines:
        if re.match(r"^!!! \w+", line):
            in_admonition = True
            result.append(line)
            continue

        if in_admonition:

            m = re.match(r"^ (\S.*)", line)
            if m:
                result.append("    " + m.group(1))
                continue

            if line.startswith("  "):
                result.append("    " + line.lstrip())
                continue

            in_admonition = False

        result.append(line)

    return "\n".join(result)


PAGE_TITLE_ICONS = {
    "Crypto":     ":material-lock:",
    "Memory":     ":material-memory:",
    "I/O":        ":material-file-lock:",
    "Vault":      ":material-safe-square-outline:",
    "GUI":        ":material-monitor:",
    "CLI":        ":material-console:",
    "Utilities":  ":material-toolbox:",
}


SECTION_ICONS = {
    "Types":               ":material-shape-outline:",
    "Functions":           ":material-function:",
    "Variables":           ":material-variable:",
    "Macros":              ":material-pound:",
    "Operators":           ":material-math-compass:",
    "Type Aliases":        ":material-link-variant:",
    "Type Details":        ":material-shape-outline:",
    "Type Alias Details":  ":material-link-variant:",
    "Function Details":    ":material-function:",
    "Variable Details":    ":material-variable:",
    "Macro Details":       ":material-pound:",
    "Operator Details":    ":material-math-compass:",
}


def add_page_title_icons(text: str) -> str:
    """
    @brief prefix generated page titles with Material icons.
    """
    for title, icon in PAGE_TITLE_ICONS.items():
        text = re.sub(rf"^# {re.escape(title)}$", f"# {icon} {title}", text, count=1, flags=re.MULTILINE)
    return text


def add_section_icons(text: str) -> str:
    """
    @brief prefix generated section headings with Material icons.
    """
    for title, icon in SECTION_ICONS.items():
        text = text.replace(f"## {title}", f"## {icon} {title}")
    return text


def trim_function_table_descriptions(text: str) -> str:
    """
    @brief keep only the first sentence in function summary rows.

    full descriptions remain in the detail section.
    """
    lines = text.split("\n")
    out = []
    in_functions_table = False

    for line in lines:
        stripped = line.strip()

        if stripped in {"## Functions", "## :material-function: Functions"}:
            in_functions_table = True
            out.append(line)
            continue


        if in_functions_table and stripped.startswith("## "):
            in_functions_table = False
            out.append(line)
            continue

        if in_functions_table and stripped.startswith("| [") and stripped.endswith("|"):
            parts = [p.strip() for p in stripped.strip("|").split("|", 1)]
            if len(parts) == 2:
                name_col, desc_col = parts
                desc_col = re.sub(r"\s+", " ", desc_col).strip()

                m = re.match(r"^(.*?\.)\s+.*$", desc_col)
                brief = m.group(1) if m else desc_col
                out.append(f"| {name_col} | {brief} |")
                continue

        out.append(line)

    return "\n".join(out)


def flatten_namespace_lists(text: str) -> str:
    """
    @brief render namespace descriptions on the same bullet as the namespace link.
    """
    lines = text.split("\n")
    out = []
    i = 0

    while i < len(lines):
        line = lines[i]
        term = line.strip()
        if term.startswith(":material-package:") or term.startswith(":material-format-section:"):
            desc = ""
            if i + 1 < len(lines):
                m = re.match(r"^:\s+(.*)$", lines[i + 1])
                if m:
                    desc = m.group(1).strip()
                    i += 1

            if desc:
                out.append(f"- {term} - {desc}")
            else:
                out.append(f"- {term}")

            i += 1
            if i < len(lines) and lines[i].strip() == "":
                i += 1
            continue

        out.append(line)
        i += 1

    return "\n".join(out)


def collect_members(index_path: Path, prefix: str) -> list[tuple[str, str, str]]:
    """
    @brief read type and function rows from a group index.

    @return name, docs-root-relative path and description triples; empty if the index is absent.
    """
    if not index_path.exists():
        return []
    text = index_path.read_text(encoding="utf-8")
    results = []

    for m in re.finditer(
        r"^\| \[([^\]]+)\]\(([^)]+)\) \|(.+)\|",
        text,
        re.MULTILINE,
    ):
        name = m.group(1)
        rel_path = m.group(2).strip()
        desc = m.group(3).strip()

        desc = re.sub(r"^@brief\s+", "", desc)
        # fragment links need the index path before the anchor.
        if rel_path.startswith("#"):
            full_path = f"{prefix}index.md{rel_path}"
        else:
            full_path = f"{prefix}{rel_path}"
        results.append((name, full_path, desc))

    return results


def collect_group_members(docs_dir: Path, group_dir: str) -> list[tuple[str, str, str]]:
    """
    @brief read members from the group and its direct subgroups.
    """
    group_index = docs_dir / group_dir / "index.md"
    prefix = f"{group_dir}/"
    members = []


    members.extend(collect_members(group_index, prefix))


    if group_index.exists():
        text = group_index.read_text(encoding="utf-8")
        for m in re.finditer(
            r":material-format-section: \[([^\]]+)\]\(([^)]+)/index\.md\)",
            text,
        ):
            sub_dir = m.group(2)

            sub_index = docs_dir / group_dir / sub_dir / "index.md"
            sub_members = collect_members(sub_index, f"{group_dir}/{sub_dir}/")
            if sub_members:
                members.extend(sub_members)
                continue
            # namespace subgroup content is top-level; nested pages are stubs.
            top_index = docs_dir / sub_dir / "index.md"
            members.extend(collect_members(top_index, f"{sub_dir}/"))

    return members


def inject_group_members(text: str, docs_dir: Path) -> str:
    """
    @brief append a flat member list after the final home-page group.

    replace existing injected entries so repeated runs do not duplicate them.
    """
    lines = text.split("\n")

    lines = [l for l in lines if not re.match(r"^-?\s*- :material-package:", l)]

    out = []
    all_members = []
    last_group_idx = -1

    for line in lines:
        out.append(line)

        m = re.match(
            r"^- :material-format-section: \[.*\]\(([^/]+)/index\.md\)",
            line,
        )
        if not m:
            continue

        last_group_idx = len(out) - 1
        group_dir = m.group(1)
        members = collect_group_members(docs_dir, group_dir)
        for name, path, desc in members:
            sentence = re.match(r"^(.*?\.)\s", desc)
            brief = sentence.group(1) if sentence else desc
            all_members.append(f"- :material-package: [{name}]({path}) - {brief}")

    if all_members and last_group_idx >= 0:
        insert_at = last_group_idx + 1
        out.insert(insert_at, "")
        for j, entry in enumerate(all_members):
            out.insert(insert_at + 1 + j, entry)

    return "\n".join(out)


def parse_version(repo_root: Path) -> str:
    """
    @brief read the three-part project version; return empty if absent.
    """
    cmakelists = repo_root / "CMakeLists.txt"
    if not cmakelists.exists():
        return ""
    content = cmakelists.read_text(encoding="utf-8")
    m = re.search(r"project\s*\([^)]*VERSION\s+(\d+\.\d+\.\d+)", content)
    return m.group(1) if m else ""


def inject_version(text: str, version: str) -> str:
    """
    @brief add the version to the home subtitle unless already present.
    """
    if not version or f"**v{version}**" in text:
        return text
    return re.sub(
        r"^(# seal)\n\n(.+)$",
        rf"\1\n\n**v{version}** | \2",
        text,
        count=1,
        flags=re.MULTILINE,
    )



def clean(text: str) -> str:

    text = re.sub(r"^\s*@author\b.*\n?", "", text, flags=re.MULTILINE)


    text = re.sub(r"@brief\s+", "", text)
    text = re.sub(r"@details\s*\n?", "", text)


    text = fix_admonition_indent(text)


    text = add_page_title_icons(text)


    text = add_section_icons(text)


    text = trim_function_table_descriptions(text)


    text = flatten_namespace_lists(text)

    return text


def main():
    docs_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("docs")

    if not docs_dir.is_dir():
        print(f"error: {docs_dir} is not a directory", file=sys.stderr)
        sys.exit(1)

    repo_root = docs_dir.resolve().parent
    version = parse_version(repo_root)
    if version:
        print(f"  version: {version}")

    changed = 0
    for md in docs_dir.rglob("*.md"):
        original = md.read_text(encoding="utf-8")
        if not is_doxide_generated(original):
            continue

        cleaned = clean(original)

        is_home = md.name == "index.md" and md.parent == docs_dir


        if is_home:
            cleaned = inject_group_members(cleaned, docs_dir)
            if version:
                cleaned = inject_version(cleaned, version)
        else:
            # rewrite only the header area before the first generated section.
            parts = cleaned.split("\n## ", 1)
            parts[0] = re.sub(
                r"^- :material-format-section:",
                "- :material-package:",
                parts[0],
                flags=re.MULTILINE,
            )
            # subgroup links must resolve to top-level content rather than nested stubs.
            parts[0] = re.sub(
                r"\]\((\w+/index\.md)\)",
                r"](../\1)",
                parts[0],
            )
            cleaned = "\n## ".join(parts)

        if cleaned != original:
            md.write_text(cleaned, encoding="utf-8")
            changed += 1
            print(f"  cleaned {md.relative_to(docs_dir)}")

    print(f"done: {changed} file(s) cleaned")


if __name__ == "__main__":
    main()

"""Pre-pass to clean doxide-generated markdown before mkdocs build.

Cleans doxide-generated markdown for MkDocs Material compatibility:
- Removes @author lines
- Strips @brief tags
- Fixes admonition indentation (1-space to 4-space)
- Adds Material icons to page titles and section headers
- Trims function summary tables to first-sentence briefs
- Flattens namespace definition lists into single-line bullets
- Injects version from CMakeLists.txt into home page subtitle

Only touches files with 'generator: doxide' frontmatter.

Usage:
    python scripts/clean_docs.py          # defaults to docs/
    python scripts/clean_docs.py path/    # custom docs directory
"""

import re
import sys
from pathlib import Path


def is_doxide_generated(text: str) -> bool:
    return "generator: doxide" in text[:200]


def fix_admonition_indent(text: str) -> str:
    """Fix doxide's 1-space admonition indent to 4-space for MkDocs Material."""
    lines = text.split("\n")
    result = []
    in_admonition = False

    for line in lines:
        if re.match(r"^!!! \w+", line):
            in_admonition = True
            result.append(line)
            continue

        if in_admonition:
            # Body line with 1-space indent
            m = re.match(r"^ (\S.*)", line)
            if m:
                result.append("    " + m.group(1))
                continue
            # Continuation with deeper indent
            if line.startswith("  "):
                result.append("    " + line.lstrip())
                continue
            # Blank or unindented line ends the admonition
            in_admonition = False

        result.append(line)

    return "\n".join(result)


PAGE_TITLE_ICONS = {
    "Crypto":     ":material-lock:",
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
    """Prepend Material icons to doxide-generated H1 page titles."""
    for title, icon in PAGE_TITLE_ICONS.items():
        text = re.sub(rf"^# {re.escape(title)}$", f"# {icon} {title}", text, count=1, flags=re.MULTILINE)
    return text


def add_section_icons(text: str) -> str:
    """Prepend Material icons to doxide-generated section headers."""
    for title, icon in SECTION_ICONS.items():
        text = text.replace(f"## {title}", f"## {icon} {title}")
    return text


def trim_function_table_descriptions(text: str) -> str:
    """Keep only a concise brief sentence in doxide function summary tables.

    Doxide occasionally emits full function details into the `Functions` table
    description column. This pass trims each function row to the first sentence
    so detailed content remains only under `Function Details`.
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

        # End table context on next section header.
        if in_functions_table and stripped.startswith("## "):
            in_functions_table = False
            out.append(line)
            continue

        if in_functions_table and stripped.startswith("| [") and stripped.endswith("|"):
            parts = [p.strip() for p in stripped.strip("|").split("|", 1)]
            if len(parts) == 2:
                name_col, desc_col = parts
                desc_col = re.sub(r"\s+", " ", desc_col).strip()
                # Keep only first sentence in summary table.
                m = re.match(r"^(.*?\.)\s+.*$", desc_col)
                brief = m.group(1) if m else desc_col
                out.append(f"| {name_col} | {brief} |")
                continue

        out.append(line)

    return "\n".join(out)


def flatten_namespace_lists(text: str) -> str:
    """Flatten doxide namespace definition lists into single-line bullets.

    Home page namespace entries are emitted as definition lists:
        :material-package: [Name](...)
        :    Description
    which renders description on the next line. Convert these to:
        - :material-package: [Name](...) - Description
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
    """Extract types and functions from a group/subgroup index.md.

    Returns list of (name, relative_path, description) tuples.
    Paths are prefixed so they're relative to the docs root.
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
        # Strip leftover @brief tag
        desc = re.sub(r"^@brief\s+", "", desc)
        # Anchor links (#func) need the index.md path prepended
        if rel_path.startswith("#"):
            full_path = f"{prefix}index.md{rel_path}"
        else:
            full_path = f"{prefix}{rel_path}"
        results.append((name, full_path, desc))

    return results


def collect_group_members(docs_dir: Path, group_dir: str) -> list[tuple[str, str, str]]:
    """Collect all types from a group and its subgroups.

    Reads the group's index.md for direct types, then reads each
    subgroup's index.md for their types.
    """
    group_index = docs_dir / group_dir / "index.md"
    prefix = f"{group_dir}/"
    members = []

    # Direct members in the group (types + functions)
    members.extend(collect_members(group_index, prefix))

    # Find subgroup links: :material-format-section: [Name](SubDir/index.md)
    if group_index.exists():
        text = group_index.read_text(encoding="utf-8")
        for m in re.finditer(
            r":material-format-section: \[([^\]]+)\]\(([^)]+)/index\.md\)",
            text,
        ):
            sub_name = m.group(1)
            sub_dir = m.group(2)
            sub_index = docs_dir / group_dir / sub_dir / "index.md"
            sub_prefix = f"{group_dir}/{sub_dir}/"
            members.extend(collect_members(sub_index, sub_prefix))

    return members


def inject_group_members(text: str, docs_dir: Path) -> str:
    """Append a flat class/function listing after the group list on the home page.

    Collects all types and functions from every group's index.md (and
    subgroup index pages), then appends them as a single bullet list
    after the last group entry.  Idempotent: strips previously-injected
    member lines before re-injecting.
    """
    lines = text.split("\n")
    # Strip previously-injected member lines (top-level and indented)
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
    """Read project VERSION from CMakeLists.txt and return 'MAJOR.MINOR.PATCH'."""
    cmakelists = repo_root / "CMakeLists.txt"
    if not cmakelists.exists():
        return ""
    content = cmakelists.read_text(encoding="utf-8")
    m = re.search(r"project\s*\([^)]*VERSION\s+(\d+\.\d+\.\d+)", content)
    return m.group(1) if m else ""


def inject_version(text: str, version: str) -> str:
    """Add version to the home page subtitle line.  Idempotent."""
    if not version or f"**v{version}**" in text:
        return text
    return re.sub(
        r"^(# sage)\n\n(.+)$",
        rf"\1\n\n**v{version}** | \2",
        text,
        count=1,
        flags=re.MULTILINE,
    )



def clean(text: str) -> str:
    # Remove standalone @author lines
    text = re.sub(r"^\s*@author\b.*\n?", "", text, flags=re.MULTILINE)

    # Strip @brief and @details tags but keep the description text
    text = re.sub(r"@brief\s+", "", text)
    text = re.sub(r"@details\s*\n?", "", text)

    # Fix admonition indentation (doxide outputs 1-space, MkDocs needs 4)
    text = fix_admonition_indent(text)

    # Add icons to page titles
    text = add_page_title_icons(text)

    # Add icons to section headers
    text = add_section_icons(text)

    # Trim over-detailed function summary table entries.
    text = trim_function_table_descriptions(text)

    # Keep namespace descriptions inline on Home/namespace listings.
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

        # Home page: inject version and group member listings
        if is_home:
            cleaned = inject_group_members(cleaned, docs_dir)
            if version:
                cleaned = inject_version(cleaned, version)
        else:
            # Group index pages: use package icon for subgroup bullets
            # and fix relative links to point to top-level content pages
            # (only in the header area, before the first ## section)
            parts = cleaned.split("\n## ", 1)
            parts[0] = re.sub(
                r"^- :material-format-section:",
                "- :material-package:",
                parts[0],
                flags=re.MULTILINE,
            )
            # Doxide generates subgroup links as relative paths (e.g.,
            # Renderer/index.md) inside group index pages (e.g.,
            # Rendering/index.md).  These resolve to stubs at
            # Rendering/Renderer/index.md instead of the actual content
            # at the top-level Renderer/index.md.  Prepend ../ to fix.
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

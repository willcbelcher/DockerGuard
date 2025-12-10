from pathlib import Path
import json
import re
import subprocess
import sys


BINARY = "./dockerguard"
RULE_LINE = re.compile(r"^\[[^\]]+\]\s+([A-Z0-9_]+):")
LINE_DETAIL = re.compile(r"^\s*Line\s+(\d+):")


# dedupe
def parse_output(text: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    seen: set[tuple[str, int]] = set()
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        m = RULE_LINE.match(lines[i].strip())
        if not m:
            i += 1
            continue
        rule = m.group(1)
        line_no = 0
        if i + 1 < len(lines):
            lm = LINE_DETAIL.match(lines[i + 1])
            if lm:
                line_no = int(lm.group(1))
                i += 1
        key = (rule, line_no)
        if key not in seen:
            seen.add(key)
            counts[rule] = counts.get(rule, 0) + 1
        i += 1
    return counts


def analyze_file(path: Path, totals: dict[str, int]) -> None:
    proc = subprocess.run(
        [str(BINARY), "-f", str(path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if proc.returncode != 0:
        sys.stderr.write(f"{path.name}: {proc.stderr}\n")
        return
    for rule, count in parse_output(proc.stdout).items():
        totals["counts"][rule] = totals["counts"].get(rule, 0) + count
        totals["files"].setdefault(rule, set()).add(path.name)


def main() -> None:
    if len(sys.argv) != 2:
        sys.stderr.write("usage: python evaluation.py path/to/Dockerfile_or_dir\n")
        sys.exit(1)
    target = Path(sys.argv[1]).resolve()
    if not target.exists():
        sys.stderr.write(f"not found: {target}\n")
        sys.exit(1)

    totals: dict[str, dict] = {"counts": {}, "files": {}}
    if target.is_file():
        analyze_file(target, totals)
    else:
        for file_path in sorted(p for p in target.iterdir() if p.is_file()):
            analyze_file(file_path, totals)

    files_by_rule = {rule: sorted(list(files)) for rule, files in totals["files"].items()}
    output = {"counts": totals["counts"], "files": files_by_rule}
    Path("evaluation_output.json").write_text(json.dumps(output, indent=2, sort_keys=True))
    print(json.dumps(output, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()


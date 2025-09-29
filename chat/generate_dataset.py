#!/usr/bin/env python3
"""
generate_dataset_selflearning.py — Dataset generator with integrated self-learning
"""

from __future__ import annotations
import argparse
import csv
import json
import logging
import os
import re
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Dict, Tuple, Optional

# Optional YAML support
try:
    import yaml
    YAML_AVAILABLE = True
except Exception:
    YAML_AVAILABLE = False

from heuristics import run_heuristics, detect_libraries_in_content, LIB_VULN_DB

# ---------------------------
# Config & Defaults
# ---------------------------
BASE_SAMPLE_DIR = "code_samples"
DEFAULT_OUTPUT = "vuln_dataset.jsonl"
CSV_OUTPUT = "vuln_dataset.csv"
CANDIDATES_FILE = "candidates.jsonl"
MAX_PROMPT_LINES = 400
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB

# ---------------------------
# Built-in rules
# ---------------------------
BUILTIN_RULES = {
    ".py": [
        {"pattern": r"\beval\s*\(", "description": "Use of eval()", "severity": "High", "cwe": ["CWE-94"], "owasp": ["A1: Injection"], "fix": "Avoid eval()", "reward_score": 1.0},
        {"pattern": r"\bexec\s*\(", "description": "Use of exec()", "severity": "High", "cwe": ["CWE-94"], "owasp": ["A1: Injection"], "fix": "Avoid exec()", "reward_score": 1.0},
    ],
    ".js": [
        {"pattern": r"\beval\s*\(", "description": "Use of eval()", "severity": "High", "cwe": ["CWE-95"], "owasp": ["A1: Injection"], "fix": "Avoid eval()", "reward_score": 1.0},
    ],
    ".generic": []
}

# ---------------------------
# Dataclasses
# ---------------------------
@dataclass
class Entry:
    file: str
    language: str
    size: int
    line_count: int
    prompt: str
    completion: str
    vulnerabilities: List[Dict]

# ---------------------------
# Rule loading
# ---------------------------
def load_rulepack(path: Optional[str]) -> Dict[str, List[Dict]]:
    if not path:
        return BUILTIN_RULES
    p = Path(path)
    if not p.exists():
        logging.warning("Rulepack not found: %s — using built-in", path)
        return BUILTIN_RULES
    try:
        if p.suffix.lower() in (".yml", ".yaml") and YAML_AVAILABLE:
            with p.open("r", encoding="utf-8") as fh:
                return yaml.safe_load(fh)
        else:
            with p.open("r", encoding="utf-8") as fh:
                return json.load(fh)
    except Exception as e:
        logging.warning("Failed to load rulepack (%s): %s — using builtin", path, e)
        return BUILTIN_RULES

# ---------------------------
# AI reward-based updater
# ---------------------------
def ai_update_rulepack(candidates_path: str, rulepack_path: Optional[str] = None, decay: float = 0.95):
    rulepack = load_rulepack(rulepack_path)
    cpath = Path(candidates_path)
    if not cpath.exists():
        return
    try:
        with cpath.open("r", encoding="utf-8") as fh:
            candidates = [json.loads(line) for line in fh if line.strip()]
    except Exception as e:
        logging.warning("Failed to read candidates: %s", e)
        return

    added_count, updated_count = 0, 0

    # decay existing rules
    for ext, rules in rulepack.items():
        for r in rules:
            r["reward_score"] = r.get("reward_score", 1.0) * decay

    # update/add patterns
    for c in candidates:
        ext = Path(c.get("file", "")).suffix.lower() or ".generic"
        lang_rules = rulepack.get(ext, [])
        pattern = c.get("candidate_pattern")
        existing = next((r for r in lang_rules if r.get("pattern") == pattern), None)
        if existing:
            existing["reward_score"] = existing.get("reward_score", 1.0) + 1.0
            updated_count += 1
        else:
            lang_rules.append({
                "pattern": pattern,
                "description": c.get("note", f"Auto-learned: {pattern}"),
                "severity": c.get("severity", "Medium"),
                "cwe": [],
                "owasp": [],
                "fix": c.get("fix", "Review and mitigate"),
                "reward_score": 1.0
            })
            rulepack[ext] = lang_rules
            added_count += 1

    out_path = Path(rulepack_path or "rulepack_autoupdated.json")
    try:
        if out_path.suffix.lower() in (".yml", ".yaml") and YAML_AVAILABLE:
            with out_path.open("w", encoding="utf-8") as fh:
                yaml.safe_dump(rulepack, fh, sort_keys=False)
        else:
            with out_path.open("w", encoding="utf-8") as fh:
                json.dump(rulepack, fh, indent=2, ensure_ascii=False)
        logging.info("AI updated rulepack: %d added, %d updated → %s", added_count, updated_count, out_path)
    except Exception as e:
        logging.warning("Failed to save rulepack: %s", e)

# ---------------------------
# Language detection
# ---------------------------
def detect_language(path: Path) -> str:
    ext = path.suffix.lower()
    if path.name.lower() == "dockerfile":
        return "Dockerfile"
    return ext or ".generic"

# ---------------------------
# File scanning
# ---------------------------
def process_file(path: Path, rulepack: Dict[str, List[Dict]]):
    try:
        size = path.stat().st_size
        if size > MAX_FILE_SIZE:
            return None
        with path.open("r", encoding="utf-8", errors="ignore") as fh:
            lines = [line.rstrip("\n") for i, line in enumerate(fh) if i < MAX_PROMPT_LINES]
            content = "\n".join(lines)
    except Exception:
        return None

    # Run heuristics from heuristics.py
    vuln_findings = run_heuristics(detect_language(path), content, lines)

    # Convert heuristics output to candidate patterns
    candidates = []
    for f in vuln_findings:
        if "type" in f and f["severity"] in {"High", "Critical"}:
            pattern = re.escape(f.get("problem_line", f.get("type", "")))
            candidates.append({
                "candidate_pattern": pattern,
                "example_context": f.get("problem_line", ""),
                "file": str(path),
                "line": f.get("line"),
                "note": f.get("ai_suggestion") or f.get("type"),
                "severity": f.get("severity"),
                "fix": f.get("fix", "")
            })

    prompt = f"Analyze {detect_language(path)} code:\n{content}"
    completion = "\n".join([f"{f.get('type','')} ({f.get('severity','?')}) [line:{f.get('line')}]" for f in vuln_findings]) or "No issues found"

    entry = Entry(
        file=str(path),
        language=detect_language(path),
        size=len(content.encode("utf-8")),
        line_count=len(content.splitlines()),
        prompt=prompt,
        completion=completion,
        vulnerabilities=vuln_findings
    )

    return entry, candidates

# ---------------------------
# Output functions
# ---------------------------
def write_jsonl(entries: List[Entry], out_path: Path):
    seen_files = set()
    with out_path.open("w", encoding="utf-8") as fh:
        for e in entries:
            if e.file in seen_files:
                continue
            seen_files.add(e.file)
            fh.write(json.dumps(asdict(e), ensure_ascii=False) + "\n")

def write_csv(entries: List[Entry], out_path: Path):
    seen_files = set()
    with out_path.open("w", encoding="utf-8", newline='') as fh:
        writer = csv.writer(fh)
        writer.writerow(["file","language","size","line_count","vuln_count","top_vulns"])
        for e in entries:
            if e.file in seen_files:
                continue
            seen_files.add(e.file)
            top = "; ".join(sorted({v.get("type","") for v in e.vulnerabilities})[:3])
            writer.writerow([e.file,e.language,e.size,e.line_count,len(e.vulnerabilities),top])

# ---------------------------
# Collect files
# ---------------------------
def collect_files(include_root: bool, base_dir: str) -> List[Path]:
    files_set = set()
    base = Path(base_dir)
    if base.exists():
        for p in base.rglob("*.*"):
            files_set.add(p.resolve())
    if include_root:
        for p in Path(".").iterdir():
            if p.is_file():
                files_set.add(p.resolve())
    return sorted(files_set, key=lambda x: str(x))

# ---------------------------
# Main scan
# ---------------------------
def run_scan(rulepack_path: Optional[str], include_root: bool, out_path: str, append_candidates: bool, ai_scan: bool):
    logging.basicConfig(level=logging.INFO)
    rulepack = load_rulepack(rulepack_path)
    files = collect_files(include_root, BASE_SAMPLE_DIR)
    entries, all_candidates = [], []

    for path in files:
        res = process_file(path, rulepack)
        if res:
            entry, candidates = res
            entries.append(entry)
            all_candidates.extend(candidates or [])

    write_jsonl(entries, Path(out_path))
    write_csv(entries, Path(CSV_OUTPUT))

    if append_candidates and all_candidates:
        # Deduplicate candidates
        unique_candidates = { (c['file'], c['candidate_pattern']): c for c in all_candidates }
        with Path(CANDIDATES_FILE).open("a", encoding="utf-8") as fh:
            for c in unique_candidates.values():
                fh.write(json.dumps(c, ensure_ascii=False) + "\n")
        logging.info("Appended %d unique candidate patterns", len(unique_candidates))
        if ai_scan:
            ai_update_rulepack(CANDIDATES_FILE, rulepack_path)

# ---------------------------
# CLI
# ---------------------------
def main_cli():
    parser = argparse.ArgumentParser(description="Self-learning vulnerability dataset generator")
    parser.add_argument("--rulepack", help="Path to rulepack JSON/YAML")
    parser.add_argument("--include-root", action="store_true")
    parser.add_argument("--out", default=DEFAULT_OUTPUT)
    parser.add_argument("--append-candidates", action="store_true")
    parser.add_argument("--ai-scan", action="store_true", help="Enable reward-based self-learning")
    args = parser.parse_args()
    run_scan(args.rulepack, args.include_root, args.out, args.append_candidates, args.ai_scan)

if __name__ == "__main__":
    main_cli()

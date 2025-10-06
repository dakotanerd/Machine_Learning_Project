#!/usr/bin/env python3
import argparse
import json
from pathlib import Path
from typing import List, Set
import re
import logging
import hashlib

from file_utils import detect_language, read_file
from heuristics import run_heuristics_file
from ast_analysis import python_ast_analysis
from generate_dataset import ai_update_rulepack, CANDIDATES_FILE, BASE_SAMPLE_DIR

MAX_LINES = 500
LOG_FILE = "chat_log.jsonl"
RULEPACK_PATH = "rulepack_autoupdated.json"
CHAT_CANDIDATES_FILE = "chat_candidates.jsonl"  # separate buffer for chat inputs

# ----------------------------
# Logging functions
# ----------------------------
def log_findings(result):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(result) + "\n")

# ----------------------------
# Collect candidates from file input (updates rulepack immediately)
# ----------------------------
def collect_file_candidates(file_path: str, findings: List[dict]):
    candidates = []
    for f in findings:
        if "type" in f and f.get("severity") in {"High", "Critical"}:
            pattern = re.escape(f.get("problem_line", f.get("type", "")))
            candidates.append({
                "candidate_pattern": pattern,
                "example_context": f.get("problem_line", ""),
                "file": file_path,
                "line": f.get("line"),
                "severity": f.get("severity"),
                "fix": f.get("fix", "")
            })
    if not candidates:
        return

    all_candidates = []
    if Path(CANDIDATES_FILE).exists():
        with open(CANDIDATES_FILE, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    all_candidates.append(json.loads(line))
    all_candidates.extend(candidates)
    unique_candidates = {(c['file'], c['candidate_pattern']): c for c in all_candidates}
    with Path(CANDIDATES_FILE).open("w", encoding="utf-8") as fh:
        for c in unique_candidates.values():
            fh.write(json.dumps(c, ensure_ascii=False) + "\n")

    # Update rulepack immediately
    ai_update_rulepack(CANDIDATES_FILE, RULEPACK_PATH)

# ----------------------------
# Collect candidates from chat input (buffered, no immediate rulepack update)
# ----------------------------
def collect_chat_candidates(snippet_id: str, findings: List[dict]):
    candidates = []
    for f in findings:
        if "type" in f and f.get("severity") in {"High", "Critical"}:
            pattern = re.escape(f.get("problem_line", f.get("type", "")))
            candidates.append({
                "candidate_pattern": pattern,
                "example_context": f.get("problem_line", ""),
                "file": snippet_id,
                "line": f.get("line"),
                "severity": f.get("severity"),
                "fix": f.get("fix", "")
            })
    if not candidates:
        return

    # Append to separate chat candidates file
    all_candidates = []
    if Path(CHAT_CANDIDATES_FILE).exists():
        with open(CHAT_CANDIDATES_FILE, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    all_candidates.append(json.loads(line))
    all_candidates.extend(candidates)

    unique_candidates = {(c['file'], c['candidate_pattern']): c for c in all_candidates}
    with Path(CHAT_CANDIDATES_FILE).open("w", encoding="utf-8") as fh:
        for c in unique_candidates.values():
            fh.write(json.dumps(c, ensure_ascii=False) + "\n")

# ----------------------------
# Merge chat candidates into main rulepack manually
# ----------------------------
def merge_chat_candidates():
    if Path(CHAT_CANDIDATES_FILE).exists():
        ai_update_rulepack(CHAT_CANDIDATES_FILE, RULEPACK_PATH)
        Path(CHAT_CANDIDATES_FILE).unlink()  # clear chat buffer after merge
        print("Chat candidates merged into rulepack.")

# ----------------------------
# Analyze a single file
# ----------------------------
def analyze_file(path: str):
    content, lines = read_file(path, max_lines=MAX_LINES)
    if content is None:
        return {"file": path, "error": f"Could not read file: {path}"}

    lang = detect_language(path)

    try:
        findings = run_heuristics_file(path, auto_log=False)
    except Exception as e:
        return {"file": path, "error": f"Heuristic analysis failed: {e}"}

    if lang == "Python":
        try:
            findings += python_ast_analysis(content, lines) or []
        except Exception as e:
            findings.append({"note": f"AST analysis failed: {e}"})

    if not findings:
        findings = [{"note": "No obvious issues found."}]

    severity_summary = {}
    for f in findings:
        sev = f.get("severity") or ("Note" if "note" in f else "Info")
        severity_summary[sev] = severity_summary.get(sev, 0) + 1

    result = {
        "file": path,
        "language": lang,
        "findings": findings,
        "severity_summary": severity_summary,
        "file_size": len(content),
        "line_count": len(lines),
    }

    log_findings(result)
    collect_file_candidates(path, findings)

    # Copy file to code_samples using content hash
    content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
    ext = Path(path).suffix
    dest = Path(BASE_SAMPLE_DIR) / f"{content_hash}{ext}"
    if not dest.exists():
        dest.parent.mkdir(parents=True, exist_ok=True)
        with open(dest, "w", encoding="utf-8") as f:
            f.write(content)

    return result

# ----------------------------
# Analyze multiple files
# ----------------------------
def chat_files(paths: List[str]):
    seen_files: Set[str] = set()
    all_files: List[str] = []

    for p in paths:
        p = Path(p).resolve()
        if p.is_file():
            all_files.append(str(p))
        elif p.is_dir():
            for f in p.rglob("*.*"):
                all_files.append(str(f.resolve()))

    results = []
    for f in all_files:
        if f in seen_files:
            continue
        seen_files.add(f)
        try:
            res = analyze_file(f)
            results.append(res)
        except Exception as e:
            results.append({"file": f, "error": f"analysis failed: {e}"})
    
    from generate_dataset_selflearning import scan_directory

    # Scan the code_samples directory and regenerate dataset
    dataset = scan_directory(BASE_SAMPLE_DIR)
    with open("dataset.jsonl", "w", encoding="utf-8") as df:
        import json
        for entry in dataset:
            df.write(json.dumps(entry) + "\n")

    return results

# ----------------------------
# Analyze chat text
# ----------------------------
def chat_text(message: str) -> str:
    lines = message.splitlines()
    if len(lines) > MAX_LINES:
        lines = lines[:MAX_LINES]
        message = "\n".join(lines)

    try:
        findings = run_heuristics_file("<chat_input>", auto_log=False) or []
    except Exception as e:
        findings = [{"note": f"Heuristic analysis failed: {e}"}]

    try:
        findings += python_ast_analysis(message, lines) or []
    except Exception as e:
        findings.append({"note": f"AST analysis failed: {e}"})

    if not findings:
        findings = [{"note": "No obvious issues found."}]

    severity_summary = {}
    for f in findings:
        sev = f.get("severity") or ("Note" if "note" in f else "Info")
        severity_summary[sev] = severity_summary.get(sev, 0) + 1

    result = {
        "language": "Python",
        "findings": findings,
        "severity_summary": severity_summary,
        "line_count": len(lines),
    }

    log_findings(result)
    collect_chat_candidates("<chat_input>", findings)
    return json.dumps(result, indent=2)

# ----------------------------
# CLI
# ----------------------------
def main():
    parser = argparse.ArgumentParser(description="Self-learning chat vulnerability analyzer")
    parser.add_argument("-f", "--file", nargs="+")
    parser.add_argument("-p", "--prompt")
    parser.add_argument("--view-log", action="store_true")
    parser.add_argument("--clear-log", action="store_true")
    parser.add_argument("--merge-chat", action="store_true", help="Merge buffered chat candidates into rulepack")
    args = parser.parse_args()

    if args.view_log:
        if Path(LOG_FILE).exists():
            print(Path(LOG_FILE).read_text(encoding="utf-8"))
        else:
            print("No log file.")
        return

    if args.clear_log:
        Path(LOG_FILE).write_text("")
        print("Log cleared.")
        return

    if args.merge_chat:
        merge_chat_candidates()
        return

    if args.file:
        results = chat_files(args.file)
        for res in results:
            print(json.dumps(res, indent=2))
    elif args.prompt:
        output = chat_text(args.prompt)
        print(output)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()

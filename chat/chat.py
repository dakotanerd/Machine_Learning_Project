#!/usr/bin/env python3
import argparse
import json
from pathlib import Path
from typing import List, Set

from file_utils import detect_language, gather_files, read_file
from heuristics import run_heuristics
from ast_analysis import python_ast_analysis

MAX_LINES = 500

def analyze_file(path: str):
    content, lines = read_file(path, max_lines=MAX_LINES)
    if content is None:
        return {"file": path, "error": f"Could not read file: {path}"}

    lang = detect_language(path)
    findings = run_heuristics(lang, content, lines) or []

    if lang == "Python":
        findings += python_ast_analysis(content, lines) or []

    if not findings:
        findings = [{"note": "No obvious issues found."}]

    severity_summary = {}
    for f in findings:
        sev = f.get("severity", "Info")
        severity_summary[sev] = severity_summary.get(sev, 0) + 1

    return {
        "file": path,
        "language": lang,
        "findings": findings,
        "severity_summary": severity_summary,
        "file_size": len(content),
        "line_count": len(lines),
    }

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
            continue  # skip duplicates
        seen_files.add(f)
        try:
            res = analyze_file(f)
            results.append(res)
        except Exception as e:
            results.append({"file": f, "error": f"analysis failed: {e}"})

    return results

def chat_text(message: str) -> str:
    return f"AI received: {message}"

def main():
    parser = argparse.ArgumentParser(description="Enhanced chat vulnerability analyzer")
    parser.add_argument("-f", "--file", nargs="+")
    parser.add_argument("-p", "--prompt")
    args = parser.parse_args()

    if args.file:
        results = chat_files(args.file)
        for res in results:
            print(json.dumps(res, indent=2))
    elif args.prompt:
        lines = args.prompt.splitlines()
        findings = run_heuristics("Python", args.prompt, lines) + python_ast_analysis(args.prompt, lines)
        if not findings:
            findings = [{"note": "No obvious issues found."}]
        severity_summary = {}
        for f in findings:
            sev = f.get("severity", "Info")
            severity_summary[sev] = severity_summary.get(sev, 0) + 1
        result = {
            "language": "Python",
            "findings": findings,
            "severity_summary": severity_summary,
            "line_count": len(lines),
        }
        print(json.dumps(result, indent=2))
    else:
        parser.print_help()

if __name__ == "__main__":
    main()

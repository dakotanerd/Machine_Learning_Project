#!/usr/bin/env python3
"""
generate_dataset.py

Scans your code sample directories (and optionally the project root) and
generates vuln_dataset.jsonl containing prompt/completion pairs.

Usage:
  python generate_dataset.py                # scans code_samples/*_samples
  python generate_dataset.py --include-root # also include files from project root
"""
import os
import json
import argparse
import re

BASE_SAMPLE_DIR = "code_samples"
OUTPUT_FILE = "vuln_dataset.jsonl"

EXT_LANG_MAP = {
    ".py": "Python",
    ".c": "C",
    ".cpp": "C++",
    ".h": "C/C++ Header",
    ".java": "Java",
    ".js": "JavaScript",
    ".go": "Go",
    ".rs": "Rust",
    ".php": "PHP",
    ".sh": "Shell",
}

# Simple heuristic completions - quick labels you can refine later
def classify_vulnerability(file_content, ext):
    ext = ext.lower()
    findings = []

    # Python checks
    if ext == ".py":
        if re.search(r"\beval\s*\(", file_content):
            findings.append("Unsafe eval usage")
        if re.search(r"\bexec\s*\(", file_content):
            findings.append("Unsafe exec usage")
        if re.search(r"\bpickle\.(loads|load)\s*\(", file_content):
            findings.append("Unsafe pickle deserialization")
        if re.search(r"requests\.(get|post)\s*\(.*verify\s*=\s*False", file_content):
            findings.append("Insecure requests verify=False")
    
    # C / C++ checks
    if ext in (".c", ".cpp", ".h"):
        if re.search(r"\bstrcpy\s*\(", file_content):
            findings.append("strcpy usage (possible buffer overflow)")
        if re.search(r"\bgets\s*\(", file_content):
            findings.append("gets() usage (unsafe)")
        if re.search(r"\bsystem\s*\(", file_content):
            findings.append("system() usage (command injection risk)")

    # Java checks
    if ext == ".java":
        if re.search(r"Runtime\.getRuntime\(\)\.exec", file_content):
            findings.append("Runtime.exec usage (command injection risk)")
        if re.search(r"\bObjectInputStream\b", file_content):
            findings.append("Potential unsafe deserialization")

    # JavaScript checks
    if ext == ".js":
        if re.search(r"\beval\s*\(", file_content):
            findings.append("eval() usage (unsafe)")
        if re.search(r"child_process\..*exec", file_content):
            findings.append("Child process exec usage (command injection)")

    # Generic check for hardcoded credentials
    if re.search(r"(password\s*[:=]\s*['\"].+['\"]|passwd\s*[:=]\s*['\"].+['\"])", file_content, re.IGNORECASE):
        findings.append("Hardcoded credentials")

    if not findings:
        findings.append("No obvious issues found")

    return " | ".join(findings)

def gather_files(include_root=False):
    files = []
    # walk sample directories matching pattern *_samples
    if os.path.exists(BASE_SAMPLE_DIR):
        for entry in os.listdir(BASE_SAMPLE_DIR):
            sub = os.path.join(BASE_SAMPLE_DIR, entry)
            if os.path.isdir(sub):
                for root, _, filenames in os.walk(sub):
                    for fn in filenames:
                        files.append(os.path.join(root, fn))
    # optionally include root-level files (like test.py)
    if include_root:
        for fn in os.listdir("."):
            if fn == OUTPUT_FILE or fn == os.path.basename(__file__):
                continue
            path = os.path.join(".", fn)
            if os.path.isfile(path):
                files.append(path)
    # remove duplicates while preserving order
    seen = set()
    uniq = []
    for p in files:
        if p not in seen:
            seen.add(p)
            uniq.append(p)
    return uniq

def main():
    parser = argparse.ArgumentParser(description="Generate vuln_dataset.jsonl from code samples")
    parser.add_argument("--include-root", action="store_true", help="Also include files from project root")
    parser.add_argument("--out", default=OUTPUT_FILE, help="Output JSONL file path")
    args = parser.parse_args()

    files = gather_files(include_root=args.include_root)
    if not files:
        print("No files found in code_samples/*_samples. Add sample files and try again.")
        return

    print(f"Found {len(files)} files. Generating dataset...")

    with open(args.out, "w", encoding="utf-8") as out_f:
        for p in files:
            try:
                with open(p, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except Exception as e:
                print(f"Skipping {p}: could not read ({e})")
                continue
            _, ext = os.path.splitext(p)
            lang = EXT_LANG_MAP.get(ext.lower(), "Unknown")
            completion = classify_vulnerability(content, ext)
            prompt = f"Analyze this {lang} code for vulnerabilities:\n{content}\n"
            entry = {"prompt": prompt, "completion": completion}
            out_f.write(json.dumps(entry) + "\n")

    print(f"Dataset written to {args.out}")

if __name__ == "__main__":
    main()

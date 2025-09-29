# generate_dataset_selflearning.py
"""
Generate a dataset for self-learning from code heuristics.

Usage:
    python generate_dataset_selflearning.py /path/to/code output_dataset.json
"""

import os
import sys
import json
from heuristics import run_heuristics

# Map severity to numeric reward
SEVERITY_REWARD = {
    "Critical": 1.0,
    "High": 1.0,
    "Medium": 0.5,
    "Low": 0.2,
    "Info": 0.2
}

def process_file(filepath, lang):
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()
    lines = content.splitlines()
    findings = run_heuristics(lang, content, lines)
    # Assign rewards based on severity
    for f in findings:
        severity = f.get("severity", "Medium")
        f["reward"] = SEVERITY_REWARD.get(severity, 0.5)
    return findings

def detect_language(filename):
    ext = filename.lower().split(".")[-1]
    if ext in ["py"]:
        return "Python"
    elif ext in ["js"]:
        return "JavaScript"
    elif ext in ["ts"]:
        return "TypeScript"
    elif ext in ["php"]:
        return "PHP"
    elif ext in ["java"]:
        return "Java"
    elif ext in ["c"]:
        return "C"
    elif ext in ["cpp", "cxx", "cc", "h", "hpp"]:
        return "C++"
    elif ext in ["go"]:
        return "Go"
    elif ext in ["rs"]:
        return "Rust"
    elif ext in ["rb"]:
        return "Ruby"
    elif ext in ["sh", "bash"]:
        return "Shell"
    elif ext in ["html", "htm"]:
        return "HTML"
    else:
        return None

def scan_directory(directory):
    dataset = []
    for root, _, files in os.walk(directory):
        for f in files:
            path = os.path.join(root, f)
            lang = detect_language(f)
            if not lang:
                continue
            try:
                findings = process_file(path, lang)
                for item in findings:
                    dataset.append({
                        "file": path,
                        "language": lang,
                        "finding": item
                    })
            except Exception as e:
                print(f"Error processing {path}: {e}")
    return dataset

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python generate_dataset_selflearning.py /path/to/code output.json")
        sys.exit(1)

    code_dir = sys.argv[1]
    out_file = sys.argv[2]

    data = scan_directory(code_dir)
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    print(f"Dataset saved to {out_file} ({len(data)} entries)")

#!/usr/bin/env python3
"""
chat.py — dataset + heuristic vulnerability analyzer (no LLM).

Usage:
  chat.py -f some_file.py
  chat.py -f some_folder/
  chat.py -p "some code snippet or keywords"

It will:
 - Try to fuzzy-match file contents against vuln_dataset.jsonl entries (best-effort).
 - If no good dataset match, run a set of heuristic checks per language and return findings.
 - Log results to chat_log.txt.
"""
import argparse
import os
import sys
import json
import re
import difflib
from datetime import datetime

# Config
DATASET_FILE = "vuln_dataset.jsonl"
LOG_FILE = "chat_log.txt"
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB
FUZZY_MATCH_THRESHOLD = 0.60

# Supported extensions -> language labels
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

# Load dataset (if available)
vuln_dataset = []
if os.path.exists(DATASET_FILE):
    try:
        with open(DATASET_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    vuln_dataset.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except Exception as e:
        print(f"[Warning] Could not read dataset file '{DATASET_FILE}': {e}")

def save_to_log(report_text, prompt_desc):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write("\n" + "="*80 + "\n")
        f.write(f"Timestamp: {ts}\n")
        f.write(f"Input: {prompt_desc}\n")
        f.write("-"*80 + "\n")
        f.write(report_text + "\n")
        f.write("="*80 + "\n\n")

def fuzzy_match_score(a, b):
    return difflib.SequenceMatcher(None, a, b).ratio()

def find_dataset_match(file_content):
    """Return best dataset completion and score, or (None, 0)."""
    best_score = 0.0
    best_completion = None
    for entry in vuln_dataset:
        prompt = entry.get("prompt", "")
        code_part = prompt.split("\n", 1)[1].strip() if "\n" in prompt else prompt
        score = fuzzy_match_score(file_content, code_part)
        if score > best_score:
            best_score = score
            best_completion = entry.get("completion", "")
    if best_score >= FUZZY_MATCH_THRESHOLD:
        return best_completion, best_score
    return None, 0.0

#########################
# Heuristic checks
#########################

def check_python(content):
    findings = []
    if re.search(r"\beval\s*\(", content):
        findings.append({
            "type": "Unsafe eval",
            "description": "Use of eval() can execute arbitrary code.",
            "fix": "Avoid eval(); validate inputs or use safer parsing."
        })
    if re.search(r"\bexec\s*\(", content):
        findings.append({
            "type": "Unsafe exec",
            "description": "Use of exec() can execute arbitrary code.",
            "fix": "Avoid exec(); use safer alternatives."
        })
    if re.search(r"subprocess\..+\bshell\s*=\s*True", content):
        findings.append({
            "type": "Subprocess shell=True",
            "description": "Using subprocess with shell=True can allow shell injection.",
            "fix": "Use list arguments and avoid shell=True."
        })
    if re.search(r"\bpickle\.(loads|load)\s*\(", content):
        findings.append({
            "type": "Unsafe deserialization (pickle)",
            "description": "Untrusted pickle data can execute arbitrary code.",
            "fix": "Do not unpickle untrusted data."
        })
    if re.search(r"requests\.(get|post)\s*\(.*verify\s*=\s*False", content):
        findings.append({
            "type": "Insecure TLS verification",
            "description": "requests called with verify=False disables SSL verification.",
            "fix": "Do not set verify=False; use proper certificates."
        })
    return findings

def check_c_cpp(content):
    findings = []
    if re.search(r"\bstrcpy\s*\(", content):
        findings.append({
            "type": "Buffer overflow (strcpy)",
            "description": "Use of strcpy can overflow buffers.",
            "fix": "Use strncpy or bounds-checked functions."
        })
    if re.search(r"\bgets\s*\(", content):
        findings.append({
            "type": "Buffer overflow (gets)",
            "description": "gets() is unsafe.",
            "fix": "Use fgets() with bounds checking."
        })
    if re.search(r"\bsystem\s*\(", content):
        findings.append({
            "type": "Untrusted command execution (system)",
            "description": "system() with untrusted data can lead to command injection.",
            "fix": "Avoid system(); sanitize inputs."
        })
    return findings

def check_java(content):
    findings = []
    lines = content.splitlines()
    for i, line in enumerate(lines, 1):  # start line numbers at 1
        if re.search(r"\bRuntime\.getRuntime\(\)\.exec\s*\(", line):
            findings.append({
                "type": "Command execution (Runtime.exec)",
                "description": "Runtime.exec can run system commands; be careful with untrusted input.",
                "fix": "Validate and sanitize inputs; prefer safer APIs.",
                "line": i
            })
        if re.search(r"\bObjectInputStream\b", line):
            findings.append({
                "type": "Potential deserialization risk",
                "description": "Java serialization can be exploited if processing untrusted data.",
                "fix": "Avoid Java serialization for untrusted data.",
                "line": i
            })
        if re.search(r'String\s+\w+\s*=\s*".*"\s*\+\s*\w+', line):
            findings.append({
                "type": "SQL Injection risk",
                "description": "User input concatenated into SQL string can lead to SQL injection.",
                "fix": "Use PreparedStatement instead of concatenation.",
                "line": i
            })
        if re.search(r'String\s+\w*password\w*\s*;', line, re.IGNORECASE):
            findings.append({
                "type": "Plaintext password storage",
                "description": "Storing passwords in plaintext is unsafe.",
                "fix": "Hash passwords before storing (bcrypt or similar).",
                "line": i
            })
        if re.search(r'new\s+File\s*\(\s*\w+\s*\)', line):
            findings.append({
                "type": "Unsafe file handling",
                "description": "User-controlled filename used without validation.",
                "fix": "Validate file paths and restrict access.",
                "line": i
            })
    return findings

def check_javascript(content):
    findings = []
    if re.search(r"\beval\s*\(", content):
        findings.append({
            "type": "Unsafe eval",
            "description": "Use of eval() can execute arbitrary JS.",
            "fix": "Avoid eval(); sanitize inputs."
        })
    if re.search(r"exec\(", content) or re.search(r"child_process\..*exec", content):
        findings.append({
            "type": "Command execution (exec)",
            "description": "Child process exec with untrusted input can lead to command injection.",
            "fix": "Use spawn with argument arrays; sanitize inputs."
        })
    if re.search(r"document\.write\s*\(", content):
        findings.append({
            "type": "DOM injection (document.write)",
            "description": "document.write with untrusted input can lead to XSS.",
            "fix": "Escape or sanitize content before DOM insertion."
        })
    return findings

def check_shell(content):
    findings = []
    if re.search(r"eval\s+", content) or re.search(r"`.*`", content):
        findings.append({
            "type": "Shell eval/backticks",
            "description": "Using eval/backticks in shell can be dangerous.",
            "fix": "Avoid eval; sanitize inputs."
        })
    return findings

def check_go(content):
    findings = []
    if re.search(r"\bexec\.Command", content):
        findings.append({
            "type": "Command execution",
            "description": "exec.Command can run system commands; watch for untrusted inputs.",
            "fix": "Sanitize inputs and prefer safer APIs."
        })
    return findings

def language_checks(language, content):
    if language == "Python":
        return check_python(content)
    if language in ("C", "C++", "C/C++ Header"):
        return check_c_cpp(content)
    if language == "Java":
        return check_java(content)
    if language == "JavaScript":
        return check_javascript(content)
    if language == "Shell":
        return check_shell(content)
    if language == "Go":
        return check_go(content)
    return []

#########################
# File analysis
#########################

def detect_language_from_ext(path):
    ext = os.path.splitext(path)[1].lower()
    return EXT_LANG_MAP.get(ext, None)

def gather_files(paths):
    """Accept files or directories and return list of files to analyze."""
    all_files = []
    for p in paths:
        if os.path.isfile(p):
            all_files.append(p)
        elif os.path.isdir(p):
            for root, _, files in os.walk(p):
                for f in files:
                    all_files.append(os.path.join(root, f))
        else:
            print(f"[Error] Path not found: {p}")
    return all_files

def analyze_file(path):
    if not os.path.exists(path):
        return {"error": f"File not found: {path}"}
    size = os.path.getsize(path)
    if size > MAX_FILE_SIZE:
        return {"error": f"File too large ({size} bytes) — max is {MAX_FILE_SIZE} bytes."}
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception as e:
        return {"error": f"Could not read file: {e}"}

    lang = detect_language_from_ext(path) or "Unknown"

    # Run heuristic checks
    findings = language_checks(lang, content)

    # Add generic hardcoded password check
    if re.search(r"(password\s*[:=]\s*['\"]\w+['\"]|passwd\s*[:=]\s*['\"]\w+['\"])", content, re.IGNORECASE):
        findings.append({
            "type": "Hardcoded credentials",
            "description": "Hardcoded passwords or credentials detected.",
            "fix": "Store secrets in environment variables or a secrets manager."
        })

    # If no findings
    if not findings:
        findings = [{"note": "No obvious issues found."}]

    # Return simplified result
    result = {
        "language": lang,
        "method": "heuristics",
        "findings": findings
    }

    return result


def analyze_text_snippet(snippet):
    ds_completion, ds_score = find_dataset_match(snippet)
    if ds_completion:
        return {"method": "dataset_match", "dataset_score": ds_score, "finding": ds_completion}
    return {"method": "heuristics", "note": "No dataset match found."}

#########################
# Main
#########################

def main():
    parser = argparse.ArgumentParser(description="Chat using local dataset/heuristics for vulnerability scanning")
    parser.add_argument("-f", "--file", nargs="+", help="Code file(s) or folder(s) to analyze")
    parser.add_argument("-p", "--prompt", help="Short code snippet or keywords to check against dataset")
    parser.add_argument("--view-log", action="store_true", help="View chat log")
    parser.add_argument("--clear-log", action="store_true", help="Clear chat log")
    args = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        return

    if args.view_log:
        if os.path.exists(LOG_FILE):
            print(open(LOG_FILE, "r", encoding="utf-8").read())
        else:
            print("No log file.")
        return

    if args.clear_log:
        open(LOG_FILE, "w").close()
        print("Log cleared.")
        return

    if args.file:
        files_to_analyze = gather_files(args.file)
        if not files_to_analyze:
            print("[Error] No valid files found.")
            parser.print_help()
            return
        for path in files_to_analyze:
            result = analyze_file(path)
            print(f"\n--- Analysis for {path} ---\n{json.dumps(result, indent=2)}\n")
            save_to_log(json.dumps(result, indent=2), f"File: {path}")

    elif args.prompt:
        result = analyze_text_snippet(args.prompt)
        pretty = json.dumps(result, indent=2)
        print(pretty)
        save_to_log(pretty, f"Prompt: {args.prompt}")

    else:
        print("[Error] Unknown or missing command.")
        parser.print_help()

if __name__ == "__main__":
    main()

# heuristics.py
"""
Main heuristic runner: applies language-specific, generic, SQL, and library vulnerability
rules. Delegates rule definitions to heuristics_rules.py.
Automatically logs findings to two JSONL files:
  - heuristics_db.jsonl       → file-level findings
  - heuristics_snippets.jsonl → snippet-level dataset for ML training
"""

import os
import re
import json
from typing import List, Tuple
from sql_patterns import SQL_PATTERNS
from heuristics_rules import HEURISTICS, GENERIC_RULES, LIB_VULN_DB

DB_PATH = "heuristics_db.jsonl"            # file-level findings
SNIPPET_DB_PATH = "heuristics_snippets.jsonl"  # snippet-level dataset

# ----------------------------
# Library detection
# ----------------------------
def detect_libraries_in_content(content: str, lang: str) -> List[str]:
    libs = set()
    # JS/TS imports
    for m in re.finditer(r"""(?:require\(|import\s+(?:.+?\s+from\s+)?|import\()\s*['"]([^'"]+)['"]""", content, re.IGNORECASE):
        libs.add(m.group(1).split("/", 1)[0].lower())
    # Python imports
    for m in re.finditer(r"^\s*from\s+([A-Za-z0-9_\.]+)\s+import", content, re.MULTILINE):
        libs.add(m.group(1).split(".", 1)[0].lower())
    for m in re.finditer(r"^\s*import\s+([A-Za-z0-9_]+)", content, re.MULTILINE):
        libs.add(m.group(1).lower())
    # PHP use statements
    for m in re.finditer(r"^\s*use\s+([A-Za-z0-9_\\]+);", content, re.MULTILINE):
        libs.add(m.group(1).split("\\")[0].lower())
    # Composer.json dependencies
    for m in re.finditer(r'"([a-z0-9_.\-\/]+)"\s*:\s*"[^\"]+"', content, re.IGNORECASE):
        pkg = m.group(1)
        if "/" in pkg or "." in pkg:
            libs.add(pkg.split("/")[0].lower())
    # Python requirements.txt
    for m in re.finditer(r"(^|\n)([A-Za-z0-9_.\-]+)(?:[=<>!~]+[^\n\r]+)?", content):
        libs.add(m.group(2).lower())
    # Maven pom.xml
    for m in re.finditer(r"<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>", content, re.IGNORECASE):
        aid = m.group(2).strip()
        libs.add(aid.lower() if aid else m.group(1).split(".")[-1].lower())
    # Go modules
    for m in re.finditer(r"^\s*require\s+([^\s]+)\s+v?[0-9\.]+", content, re.MULTILINE):
        libs.add(m.group(1).split("/")[0].lower())
    # Rust Cargo.toml
    for m in re.finditer(r"^\s*([A-Za-z0-9_\-]+)\s*=\s*['\"][^'\"]+['\"]", content, re.MULTILINE):
        libs.add(m.group(1).lower())
    # Filter obvious false positives
    filtered = set()
    for name in libs:
        if len(name) < 2 or name.lower() in {"from", "import", "require", "module", "class", "def", "function", "var", "const", "let"}:
            continue
        filtered.add(name)
    return sorted(filtered)

# ----------------------------
# Language detection by file extension
# ----------------------------
def detect_language_from_ext(path: str) -> str:
    ext = os.path.splitext(path)[1].lower()
    mapping = {
        ".py": "Python",
        ".c": "C",
        ".cpp": "C++", ".cc": "C++", ".cxx": "C++", ".hpp": "C++", ".h": "C++",
        ".java": "Java",
        ".js": "JavaScript",
        ".ts": "TypeScript",
        ".php": "PHP",
        ".go": "Go",
        ".rs": "Rust",
        ".rb": "Ruby",
        ".sh": "Shell", ".bash": "Shell"
    }
    return mapping.get(ext, "Unknown")

# ----------------------------
# Read file
# ----------------------------
def read_file(path: str) -> Tuple[str, List[str]]:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()
    return content, content.splitlines()

# ----------------------------
# Append findings to JSONL database
# ----------------------------
def append_to_db(findings: List[dict], db_path=DB_PATH):
    with open(db_path, "a", encoding="utf-8") as f:
        for finding in findings:
            f.write(json.dumps(finding) + "\n")

def append_snippets_to_db(snippets: List[dict], db_path=SNIPPET_DB_PATH):
    with open(db_path, "a", encoding="utf-8") as f:
        for snippet in snippets:
            f.write(json.dumps(snippet) + "\n")

# ----------------------------
# Detect unsanitized input (C/C++)
# ----------------------------
def detect_unsanitized_input(content: str, lines: List[str], lang: str) -> List[dict]:
    findings = []
    if lang not in ("C", "C++"):
        return findings
    cin_pattern = re.compile(r'\bcin\s*>>\s*([A-Za-z_]\w*)')
    cout_pattern_template = r'\bcout\s*<<\s*{var}\b'
    sanitizer_re = re.compile(r'\b(sanitize_|escape_|html_escape|url_encode)\b', re.IGNORECASE)
    for m in cin_pattern.finditer(content):
        var = m.group(1)
        start = m.start()
        line_idx = content[:start].count("\n")
        cout_re = re.compile(cout_pattern_template.format(var=re.escape(var)))
        for m2 in cout_re.finditer(content):
            cout_start = m2.start()
            if cout_start <= start:
                continue
            cout_line_idx = content[:cout_start].count("\n")
            between = "\n".join(lines[line_idx:cout_line_idx+1])
            if sanitizer_re.search(between):
                continue
            problem_line = lines[cout_line_idx] if cout_line_idx < len(lines) else ""
            findings.append({
                "type": "Unsanitized input echoed",
                "severity": "Medium",
                "problem_line": problem_line.strip(),
                "fix": f"Sanitize or validate variable '{var}' before output.",
                "line": cout_line_idx + 1,
            })
    return findings

# ----------------------------
# Extract code snippets
# ----------------------------
def extract_snippets(lang: str, content: str):
    """
    Regex-based function/method extractor.
    Returns [(snippet_code, start_line, end_line)]
    """
    snippets = []
    if lang in ("Python", "JavaScript", "TypeScript", "Java", "C", "C++", "Go", "Rust", "PHP"):
        pattern = re.compile(r"^\s*(def |function |class |public |private |fn |void )", re.MULTILINE)
        starts = [m.start() for m in pattern.finditer(content)]
        starts.append(len(content))
        for i in range(len(starts) - 1):
            snippet = content[starts[i]:starts[i+1]]
            start_line = content[:starts[i]].count("\n") + 1
            end_line = content[:starts[i+1]].count("\n")
            snippets.append((snippet, start_line, end_line))
    return snippets or [(content, 1, len(content.splitlines()))]

# ----------------------------
# Run heuristics on content
# ----------------------------
def run_heuristics(lang: str, content: str, lines: List[str]) -> List[dict]:
    findings = []

    # Language-specific rules
    for pattern, typ, severity, fix in HEURISTICS.get(lang, []):
        try:
            for m in re.finditer(pattern, content, re.IGNORECASE | re.DOTALL):
                line_num = content[:m.start()].count("\n")
                problem_line = lines[line_num] if line_num < len(lines) else ""
                findings.append({
                    "type": typ,
                    "severity": severity,
                    "problem_line": problem_line.strip(),
                    "fix": fix,
                    "line": line_num + 1,
                })
        except re.error:
            continue

    # Generic rules
    for pattern, typ, severity, fix in GENERIC_RULES:
        try:
            for m in re.finditer(pattern, content, re.IGNORECASE | re.DOTALL):
                line_num = content[:m.start()].count("\n")
                problem_line = lines[line_num] if line_num < len(lines) else ""
                findings.append({
                    "type": typ,
                    "severity": severity,
                    "problem_line": problem_line.strip(),
                    "fix": fix,
                    "line": line_num + 1,
                })
        except re.error:
            continue

    # SQL patterns
    if lang in SQL_PATTERNS:
        for pattern, typ, severity, fix in SQL_PATTERNS[lang]:
            try:
                for m in re.finditer(pattern, content, re.IGNORECASE | re.DOTALL):
                    line_num = content[:m.start()].count("\n")
                    problem_line = lines[line_num] if line_num < len(lines) else ""
                    findings.append({
                        "type": typ,
                        "severity": severity,
                        "problem_line": problem_line.strip(),
                        "fix": fix,
                        "line": line_num + 1,
                    })
            except re.error:
                continue

    # Library detection & vulnerabilities
    libs = detect_libraries_in_content(content, lang)
    for pkg in libs:
        if pkg.lower() in LIB_VULN_DB:
            info = LIB_VULN_DB[pkg.lower()]
            findings.append({
                "type": f"Dependency: {pkg}",
                "severity": info.get("severity", "Medium"),
                "problem_line": f"Detected dependency reference to '{pkg}'",
                "fix": info.get("fix", ""),
                "line": None,
            })

    # Deduplicate
    seen = set()
    deduped = []
    for f in findings:
        key = (f.get("type"), f.get("line"), (f.get("problem_line") or "")[:200])
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    if not deduped:
        deduped = [{"note": "No obvious issues found."}]
    return deduped

# ----------------------------
# Run heuristics on a file & log both styles
# ----------------------------
def run_heuristics_file(path: str, auto_log: bool = True):
    content, lines = read_file(path)
    lang = detect_language_from_ext(path)
    base_findings = run_heuristics(lang, content, lines)
    extra_findings = detect_unsanitized_input(content, lines, lang)

    # Merge findings
    all_findings = []
    seen = set()
    for f in base_findings + extra_findings:
        key = (f.get("type"), f.get("line"), (f.get("problem_line") or "")[:200])
        if key not in seen:
            seen.add(key)
            all_findings.append(f)
    if not all_findings:
        all_findings = [{"note": "No obvious issues found."}]

    # Auto log (file-level)
    if auto_log:
        append_to_db(all_findings)

    # Snippet-level dataset
    snippets = extract_snippets(lang, content)
    snippet_records = []
    for code, start, end in snippets:
        findings_here = [f for f in all_findings if f.get("line") and start <= f["line"] <= end]
        record = {
            "file": path,
            "lang": lang,
            "start_line": start,
            "end_line": end,
            "code": code.strip(),
            "label": 1 if findings_here else 0,   # 1 = vulnerable, 0 = safe
            "findings": findings_here,
        }
        snippet_records.append(record)

    if auto_log:
        append_snippets_to_db(snippet_records)

    return all_findings

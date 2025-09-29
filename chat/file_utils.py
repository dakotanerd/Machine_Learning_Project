from pathlib import Path
from typing import Tuple, List

# Map extensions to languages
EXT_TO_LANG = {
    ".py": "Python",
    ".js": "JavaScript",
    ".ts": "TypeScript",
    ".php": "PHP",
    ".java": "Java",
    ".c": "C",
    ".cpp": "C++",
    ".cxx": "C++",
    ".c++": "C++",
    ".h": "C++",
    ".hpp": "C++",
    ".go": "Go",
    ".rs": "Rust",
    ".rb": "Ruby",
    ".sh": "Shell",
    ".bash": "Shell",
    ".html": "HTML",
    ".htm": "HTML",
}

def detect_language(filename: str) -> str:
    filename = filename.lower()
    for ext, lang in EXT_TO_LANG.items():
        if filename.endswith(ext):
            return lang
    return "Unknown"

def read_file(path: str, max_lines: int = 500) -> Tuple[str, List[str]]:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
            if len(lines) > max_lines:
                lines = lines[:max_lines]
            content = "".join(lines)
            return content, lines
    except Exception:
        return None, []

def gather_files(paths: list) -> list:
    all_files = []
    for p in paths:
        p = Path(p).resolve()
        if p.is_file():
            all_files.append(str(p))
        elif p.is_dir():
            for f in p.rglob("*.*"):
                all_files.append(str(f.resolve()))
    return all_files

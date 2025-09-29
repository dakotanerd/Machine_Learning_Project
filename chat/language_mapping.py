# language_mapping.py
EXT_TO_LANG = {
    ".py": "Python",
    ".js": "JavaScript",
    ".ts": "TypeScript",
    ".php": "PHP",
    ".java": "Java",
    ".c": "C",
    ".cpp": "C++",
    ".c++": "C++",
    ".h": "C++",
    ".go": "Go",
    ".rs": "Rust",
    ".rb": "Ruby",
    ".sh": "Shell",
    ".bash": "Shell",
    ".html": "HTML",
    ".htm": "HTML",
}

def detect_language(filename: str) -> str:
    for ext, lang in EXT_TO_LANG.items():
        if filename.lower().endswith(ext):
            return lang
    return "Unknown"

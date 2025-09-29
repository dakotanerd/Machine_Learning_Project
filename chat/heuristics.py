# heuristics.py
"""
Expanded heuristic rulepack for many languages, with library-detection & library-vulnerability
notifications.

Behavior:
- Runs language-specific regex checks (dangerous functions, insecure patterns).
- Runs generic rules (hardcoded tokens, path traversal, weak crypto, etc.).
- Attempts to detect libraries/packages used in the file or in dependency manifest snippets.
  If a detected library appears in LIB_VULN_DB, a finding is added with advisory text.
- Deduplicates findings and returns a list (or a default "No obvious issues found.").
"""

import re
from typing import List, Dict
from sql_patterns import SQL_PATTERNS

# ----------------------------
# Simple library vulnerability DB
# Expand this mapping with more packages, versions, and advisories as needed.
# Keys are lowercase package names; values: dict with advisory text + severity + remedy.
# ----------------------------
LIB_VULN_DB = {
    # JavaScript / Node
    "lodash": {
        "advisory": "Known prototype pollution issues in older lodash versions (<4.17.21).",
        "severity": "High",
        "fix": "Upgrade lodash to latest stable (>=4.17.21)."
    },
    "jquery": {
        "advisory": "Older jquery versions have XSS or prototype pollution issues.",
        "severity": "Medium",
        "fix": "Upgrade to latest patch of jquery."
    },
    "express": {
        "advisory": "Certain middleware misconfiguration can lead to vulnerabilities; check version.",
        "severity": "Medium",
        "fix": "Keep express and middleware up-to-date; use helmet for headers."
    },
    "underscore": {
        "advisory": "Older versions may have prototype pollution issues.",
        "severity": "Medium",
        "fix": "Upgrade to maintained versions or replace usage."
    },

    # Python
    "pyyaml": {
        "advisory": "yaml.load() is unsafe if loader isn't specified (can lead to code execution).",
        "severity": "High",
        "fix": "Use yaml.safe_load() or specify SafeLoader."
    },
    "django": {
        "advisory": "Certain outdated Django versions have critical RCE/XSS/CSRF related issues.",
        "severity": "High",
        "fix": "Upgrade to supported Django version and follow security guide."
    },

    # PHP / Composer
    "symfony/http-foundation": {
        "advisory": "Previous vulnerable versions have issues. Check composer advisories.",
        "severity": "Medium",
        "fix": "Upgrade symfony components."
    },

    # Java (Maven)
    "log4j": {
        "advisory": "Log4Shell (CVE-2021-44228) is critical; affected versions of log4j 2.x allow remote code execution.",
        "severity": "Critical",
        "fix": "Upgrade to log4j >= 2.17.1 (or follow vendor guidance)."
    },

    # Ruby (gems)
    "rails": {
        "advisory": "Older Rails versions may have multiple security advisories.",
        "severity": "High",
        "fix": "Upgrade Rails and apply security patches."
    },

    # Go modules (module path keys simplified)
    "github.com/dgrijalva/jwt-go": {
        "advisory": "dgrijalva/jwt-go has unmaintained versions; use maintained forks.",
        "severity": "High",
        "fix": "Migrate to github.com/golang-jwt/jwt or maintained alternatives."
    },

    # Rust crates (example)
    "serde_json": {
        "advisory": "Be cautious with untrusted deserialization patterns.",
        "severity": "Medium",
        "fix": "Validate inputs and avoid unsafe deserialization patterns."
    },

    # Generic examples to surface package-related findings
    "requests": {
        "advisory": "Using requests with verify=False disables TLS verification.",
        "severity": "High",
        "fix": "Ensure TLS verification is enabled and certificates are validated."
    },

    # Add more packages / advisories below as needed
}

# ----------------------------
# Language specific heuristics
# (kept concise; you can expand further)
# ----------------------------
HEURISTICS = {
    "Python": [
        (r"\beval\s*\(", "Unsafe eval()", "High", "Avoid eval(); use ast.literal_eval or strict parsing."),
        (r"\bexec\s*\(", "Unsafe exec()", "High", "Avoid exec(); restrict execution or remove."),
        (r"subprocess\..+\bshell\s*=\s*True", "subprocess(..., shell=True)", "High", "Use list args and avoid shell=True."),
        (r"pickle\.(loads|load)\s*\(", "Unsafe pickle deserialization", "High", "Do not unpickle untrusted data."),
        (r"yaml\.load\s*\(", "Unsafe yaml.load()", "High", "Use yaml.safe_load() or SafeLoader."),
        (r"requests\.get\(.+verify\s*=\s*False", "TLS verification disabled", "High", "Enable certificate verification."),
    ],
    "JavaScript": [
        (r"\beval\s*\(", "Unsafe eval()", "High", "Avoid eval(); use safer parsing or JSON.parse."),
        (r"new Function\(", "Dynamic function constructor", "High", "Avoid dynamic code evaluation."),
        (r"child_process\.(exec|execSync)\s*\(", "child_process.exec used", "High", "Use spawn with args; validate inputs."),
    ],
    "TypeScript": [
        (r"\beval\s*\(", "Unsafe eval()", "High", "Avoid eval(); use safer alternatives."),
    ],
    "PHP": [
        # Code execution / eval / shell
        (r"\beval\s*\(", "Unsafe eval()", "High", "Avoid eval(); use safer parsing."),
        (r"\bexec\s*\(", "Command execution (exec)", "High", "Sanitize inputs and use safe APIs."),
        (r"\bshell_exec\s*\(", "Shell execution (shell_exec)", "High", "Avoid shell_exec; sanitize inputs."),
        (r"\bpassthru\s*\(", "Shell execution (passthru)", "High", "Avoid passthru; sanitize inputs."),
        (r"\bsystem\s*\(", "Shell execution (system)", "High", "Avoid system; sanitize inputs."),
        (r"\bpopen\s*\(", "Shell execution (popen)", "High", "Avoid popen; sanitize inputs."),
        (r"\bproc_open\s*\(", "Shell execution (proc_open)", "High", "Avoid proc_open; sanitize inputs."),

        # File inclusion / file operations
        (r"\binclude\s*\(", "Dynamic include", "High", "Avoid dynamic includes; validate file names."),
        (r"\brequire\s*\(", "Dynamic require", "High", "Avoid dynamic require; validate file names."),
        (r"\binclude_once\s*\(", "Dynamic include_once", "High", "Avoid dynamic includes; validate file names."),
        (r"\brequire_once\s*\(", "Dynamic require_once", "High", "Avoid dynamic require_once; validate file names."),
        (r"\bfile_get_contents\s*\(", "File read", "Medium", "Validate input paths to prevent local file disclosure."),
        (r"\bfile_put_contents\s*\(", "File write", "Medium", "Validate paths and sanitize input."),

        # SQL / database risks
        (r"\bmysql_query\s*\(", "Deprecated mysql_query (SQLi risk)", "High", "Use prepared statements (PDO or mysqli)."),
        (r"\bmysqli_query\s*\(", "Potential SQL injection", "High", "Use prepared statements."),
        (r"\bPDO->query\s*\(", "Potential SQL injection", "High", "Use prepared statements with bound parameters."),
        (r"\bPDO->exec\s*\(", "Potential SQL injection", "High", "Use prepared statements."),

        # Input validation / sanitization
        (r"\$_(GET|POST|REQUEST)\[", "Unvalidated user input", "High", "Validate and sanitize all user input."),
        (r"\bfilter_input\s*\(", "Input validation missing context", "Medium", "Ensure correct filter types are used."),

        # Cryptography / hashing issues
        (r"\bmd5\s*\(", "Weak hashing (MD5)", "Medium", "Use SHA-256 or bcrypt/Argon2."),
        (r"\bsha1\s*\(", "Weak hashing (SHA1)", "Medium", "Use SHA-256 or bcrypt/Argon2."),
        (r"\bbase64_decode\s*\(", "Potential hidden code (base64_decode)", "Medium", "Check input before decoding."),

        # XSS / HTML output
        (r"echo\s+[^;]+", "Potential XSS risk", "Medium", "Escape HTML output using htmlspecialchars or equivalent."),
        (r"print\s+[^;]+", "Potential XSS risk", "Medium", "Escape HTML output using htmlspecialchars or equivalent."),

        # File upload / deserialization
        (r"\bmove_uploaded_file\s*\(", "File upload risk", "High", "Validate file type and path before moving."),
        (r"\bunserialize\s*\(", "Unsafe deserialization", "High", "Avoid unserializing untrusted data."),

        # Cookie / session / CSRF risks
        (r"\$_COOKIE", "Unvalidated cookie", "Medium", "Validate cookie data before use."),
        (r"session_start\s*\(", "Session usage", "Medium", "Ensure secure session handling."),
        (r"\$_SESSION", "Potential session misuse", "Medium", "Validate session values before use."),

        # Deprecated / risky functions
        (r"\bereg\s*\(", "Deprecated function (ereg)", "Medium", "Use preg_match instead."),
        (r"\bsplit\s*\(", "Deprecated function (split)", "Medium", "Use explode() or preg_split()."),
        (r"\bmysql_(connect|select_db|fetch_array)\s*\(", "Deprecated MySQL API", "High", "Use mysqli or PDO."),

        # Hardcoded credentials / API keys
        (r"(password\s*[:=]\s*['\"]\w+['\"]|passwd\s*[:=]\s*['\"]\w+['\"])", "Hardcoded credentials", "High", "Use environment variables."),
        (r"API[_-]?KEY\s*[:=]\s*['\"].+['\"]", "Hardcoded API key", "High", "Store API keys securely."),

        # Potential vulnerable libraries (common PHP libs)
        (r"require\s*\(['\"]vendor/autoload\.php['\"]\)", "Composer dependencies loaded", "Info", "Check vendor libraries for known vulnerabilities."),
        (r"use\s+PHPMailer;", "PHPMailer usage", "Info", "Ensure PHPMailer version is secure."),
        (r"use\s+SwiftMailer;", "SwiftMailer usage", "Info", "Ensure SwiftMailer version is secure."),
        (r"use\s+Guzzle;", "Guzzle HTTP client usage", "Info", "Ensure Guzzle version is secure."),

        # Miscellaneous common risky patterns
        (r"preg_replace\s*\(.*\/e.*\)", "preg_replace /e modifier (code execution)", "High", "Use preg_replace_callback instead."),
        (r"create_function\s*\(", "Dynamic function creation", "High", "Avoid create_function; use closures."),
        (r"\bassert\s*\(", "Assert usage (code execution)", "High", "Avoid assert on untrusted input."),
        (r"\bglob\s*\(", "File pattern reading", "Medium", "Validate file paths and patterns."),
        (r"\bchmod\s*\(", "Changing file permissions", "Medium", "Avoid insecure permissions."),
        (r"\bunlink\s*\(", "File deletion", "Medium", "Validate file paths before deleting."),
        (r"\bcopy\s*\(", "File copy", "Medium", "Validate source and destination."),
        (r"\brename\s*\(", "File rename", "Medium", "Validate source and destination."),
        (r"\btempnam\s*\(", "Temporary file creation", "Medium", "Ensure temp files are secure."),
        (r"\bparse_ini_file\s*\(", "Parsing INI file", "Medium", "Validate configuration files."),
        (r"\bhighlight_file\s*\(", "Code exposure risk", "Medium", "Avoid exposing source code."),
        (r"\bphpinfo\s*\(", "Information disclosure", "Medium", "Remove phpinfo() calls in production."),
        (r"\bvar_dump\s*\(", "Potential sensitive data exposure", "Low", "Remove var_dump() in production."),
    ],

    "Java": [
        (r"Runtime\s*\.\s*getRuntime\s*\(\)\s*\.exec\s*\(", "Runtime.exec() usage", "High", "Avoid dynamic command execution; sanitize inputs."),
        (r"Cipher\.getInstance\(['\"]?AES/ECB", "Use of AES/ECB mode", "High", "Use AES/GCM or CBC with proper IV."),
    ],
    "C": [
        (r"\bstrcpy\s*\(", "Unsafe strcpy", "High", "Use strncpy or bounds-checked functions."),
        (r"\bgets\s*\(", "Unsafe gets", "High", "Use fgets with size limits."),
    ],
    "C++": [
        (r"\bstrcpy\s*\(", "Unsafe strcpy", "High", "Prefer std::string or strncpy."),
        (r"\bmemcpy\s*\(", "Unbounded memcpy", "High", "Validate sizes before memcpy."),
    ],
    "Go": [
        (r"os\.Exec\s*\(", "os.Exec usage", "High", "Avoid direct exec; validate inputs."),
        (r"http\.ListenAndServe\(", "Use of default HTTP server without TLS", "High", "Use TLS and proper server configuration."),
    ],
    "Rust": [
        (r"\bunsafe\s*{", "Unsafe block", "High", "Minimize unsafe usage and document reasons."),
    ],
    "Ruby": [
        (r"\beval\s*\(", "Unsafe eval()", "High", "Avoid eval; use safer parsing."),
        (r"system\s*\(", "system() execution", "High", "Sanitize inputs before executing system calls."),
    ],
    "Shell": [
        (r"\brm\s+-rf\s+/", "Dangerous rm -rf /", "Critical", "Never run rm -rf on root; validate input."),
        (r"`[^`]+`", "Backtick command execution", "High", "Avoid backticks; use safer APIs."),
        (r"\beval\s+", "eval in shell", "High", "Avoid eval; prefer safe parsing."),
    ],
    "HTML": [
        (r"<script[^>]*>.*</script>", "Inline script tag", "Medium", "Avoid inline scripts; use CSP and safe JS."),
        (r"on\w+\s*=", "Inline event handler", "Medium", "Avoid inline handlers; attach via JS."),
    ],
}

# Generic rules that apply to any language
GENERIC_RULES = [
    (r"(?:api[_-]?key|apikey|secret|access_token|auth_token)\s*[:=]\s*['\"][A-Za-z0-9\-\._=+/]+['\"]",
     "Hardcoded secret/token", "High", "Move secrets to environment variables or a secrets manager."),
    (r"(?:password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{4,}['\"]",
     "Hardcoded password", "High", "Do not store passwords in source code."),
    (r"MD5\s*\(|\bmd5\(", "Use of MD5", "Medium", "Use SHA-256 or stronger hashing."),
    (r"sha1\s*\(|\bSHA1\b", "Use of SHA-1", "Medium", "Use SHA-256 or better."),
    (r"verify\s*=\s*False|create_unverified_context", "TLS verification disabled", "High", "Do not disable TLS verification in production."),
    (r"(\.\./|\.\.\\)", "Path traversal sequence", "High", "Normalize and validate file paths; restrict to safe directories."),
    (r"\b(unpickle|pickle\.loads|pickle\.load|yaml\.load|Marshal\.load)\b", "Unsafe deserialization", "High", "Avoid deserializing untrusted input."),
    (r"log\.\w+\(.+%s.+\)", "Potential log format injection", "Medium", "Use structured logging and sanitize inputs."),
]

# ----------------------------
# Library detection: regexes to extract package names from code + manifest snippets
# Returns list of package names (lowercased)
# ----------------------------
def detect_libraries_in_content(content: str, lang: str) -> List[str]:
    libs = set()
    # Generic import/require patterns
    # JS/TS: require('pkg'), import pkg from 'pkg', import 'pkg'
    for m in re.finditer(r"""(?:require\(|import\s+(?:.+?\s+from\s+)?|import\()\s*['"]([^'"]+)['"]""", content, re.IGNORECASE):
        libs.add(m.group(1).split("/", 1)[0].lower())
    # CommonJS require without parentheses: var x = require 'pkg' (rare) -- skip
    # Python imports: import pkg, from pkg import ...
    for m in re.finditer(r"^\s*from\s+([A-Za-z0-9_\.]+)\s+import", content, re.MULTILINE):
        libs.add(m.group(1).split(".", 1)[0].lower())
    for m in re.finditer(r"^\s*import\s+([A-Za-z0-9_]+)", content, re.MULTILINE):
        libs.add(m.group(1).lower())
    # PHP includes / composer: use statements and composer.json snippet detection
    for m in re.finditer(r"^\s*use\s+([A-Za-z0-9_\\]+);", content, re.MULTILINE):
        # php use: namespace\Class ; get vendor/package style? keep vendor
        libs.add(m.group(1).split("\\")[0].lower())
    # PHP composer.json dependency snippet: "package/name": "version"
    for m in re.finditer(r'"([a-z0-9_.\-\/]+)"\s*:\s*"[^\"]+"', content, re.IGNORECASE):
        # if we see a package-style string, include it
        pkg = m.group(1)
        # skip JSON keys like "name" or "version"
        if "/" in pkg or "." in pkg:
            libs.add(pkg.split("/")[0].lower())
    # Python requirements.txt style: lines like "package==1.2.3"
    for m in re.finditer(r"(^|\n)([A-Za-z0-9_.\-]+)(?:[=<>!~]+[^\n\r]+)?", content):
        name = m.group(2)
        # heuristic: if line contains '==' or starts with a package-ish, add
        # avoid matching arbitrary words; require line-level check
        # check the substring that includes the match to see if it's standalone
        start = m.start(2)
        # ensure not inside code line; but this is heuristic
        libs.add(name.lower())
    # Maven pom.xml: <dependency><groupId>org.apache.logging.log4j</groupId>
    for m in re.finditer(r"<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>", content, re.IGNORECASE):
        gid = m.group(1).strip()
        aid = m.group(2).strip()
        libs.add(aid.lower() if aid else gid.split(".")[-1].lower())
    # go.mod require lines: require github.com/some/pkg v1.2.3
    for m in re.finditer(r"^\s*require\s+([^\s]+)\s+v?[0-9\.]+", content, re.MULTILINE):
        libs.add(m.group(1).split("/")[0].lower())
    # Cargo.toml: dependencies = { serde = "1.0" } or serde = "1.0"
    for m in re.finditer(r"^\s*([A-Za-z0-9_\-]+)\s*=\s*['\"][^'\"]+['\"]", content, re.MULTILINE):
        libs.add(m.group(1).lower())

    # Filter out obvious false positives: single-letter tokens, common keywords
    filtered = set()
    for name in libs:
        if len(name) < 2:
            continue
        if name.lower() in {"from", "import", "require", "module", "class", "def", "function", "var", "const", "let"}:
            continue
        filtered.add(name)
    return sorted(filtered)


# ----------------------------
# Main heuristics runner (language-specific + generic + SQL + library checks)
# ----------------------------
def run_heuristics(lang: str, content: str, lines: List[str]):
    findings = []

    lang_key = (lang or "").strip()

    # Language-specific rules
    for pattern, typ, severity, fix in HEURISTICS.get(lang_key, []):
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
                    "ai_suggestion": ""
                   
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
                    "ai_suggestion": ""
                })
        except re.error:
            continue

    # SQL patterns per-language (if provided)
    try:
        if lang_key in SQL_PATTERNS:
            for pattern, typ, severity, fix in SQL_PATTERNS[lang_key]:
                for m in re.finditer(pattern, content, re.IGNORECASE | re.DOTALL):
                    line_num = content[:m.start()].count("\n")
                    problem_line = lines[line_num] if line_num < len(lines) else ""
                    findings.append({
                        "type": typ,
                        "severity": severity,
                        "problem_line": problem_line.strip(),
                        "fix": fix,
                        "line": line_num + 1,
                        "ai_suggestion": ""
                    })
    except Exception:
        pass

    # Library detection & vulnerability checks
    try:
        libs = detect_libraries_in_content(content, lang_key)
        for pkg in libs:
            pkg_key = pkg.lower()
            if pkg_key in LIB_VULN_DB:
                info = LIB_VULN_DB[pkg_key]
                # create a finding related to package vulnerability
                findings.append({
                    "type": f"Dependency: {pkg}",
                    "severity": info.get("severity", "Medium"),
                    "problem_line": f"Detected dependency reference to '{pkg}'",
                    "fix": info.get("fix", ""),
                    "line": None,
                    "ai_suggestion": info.get("advisory", "")
                })
    except Exception:
        pass

    # Deduplicate by (type, line, problem_line)
    seen = set()
    deduped = []
    for f in findings:
        key = (f.get("type"), f.get("line"), (f.get("problem_line") or "")[:200])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(f)

    if not deduped:
        deduped = [{"note": "No obvious issues found."}]

    return deduped


def run_heuristics_selflearning(lang: str, content: str, lines: List[str]):
    findings = []
    candidates = []

    lang_key = (lang or "").strip()

    # 1️⃣ Language-specific rules
    for pattern, typ, severity, fix in HEURISTICS.get(lang_key, []):
        try:
            for m in re.finditer(pattern, content, re.IGNORECASE | re.DOTALL):
                line_num = content[:m.start()].count("\n")
                problem_line = lines[line_num] if line_num < len(lines) else ""
                
                finding = {
                    "type": typ,
                    "severity": severity,
                    "problem_line": problem_line.strip(),
                    "fix": fix,
                    "line": line_num + 1,
                    "ai_suggestion": ""
                }
                findings.append(finding)

                # Candidate pattern for AI self-learning
                candidates.append({
                    "candidate_pattern": re.escape(m.group(0)),
                    "example_context": problem_line.strip(),
                    "line": line_num + 1,
                    "reward_score": None  # can be updated after AI confirms validity
                })
        except re.error:
            continue

    # 2️⃣ Generic rules
    for pattern, typ, severity, fix in GENERIC_RULES:
        try:
            for m in re.finditer(pattern, content, re.IGNORECASE | re.DOTALL):
                line_num = content[:m.start()].count("\n")
                problem_line = lines[line_num] if line_num < len(lines) else ""

                finding = {
                    "type": typ,
                    "severity": severity,
                    "problem_line": problem_line.strip(),
                    "fix": fix,
                    "line": line_num + 1,
                    "ai_suggestion": ""
                }
                findings.append(finding)

                candidates.append({
                    "candidate_pattern": re.escape(m.group(0)),
                    "example_context": problem_line.strip(),
                    "line": line_num + 1,
                    "reward_score": None
                })
        except re.error:
            continue

    # 3️⃣ SQL patterns per-language
    try:
        if lang_key in SQL_PATTERNS:
            for pattern, typ, severity, fix in SQL_PATTERNS[lang_key]:
                for m in re.finditer(pattern, content, re.IGNORECASE | re.DOTALL):
                    line_num = content[:m.start()].count("\n")
                    problem_line = lines[line_num] if line_num < len(lines) else ""

                    finding = {
                        "type": typ,
                        "severity": severity,
                        "problem_line": problem_line.strip(),
                        "fix": fix,
                        "line": line_num + 1,
                        "ai_suggestion": ""
                    }
                    findings.append(finding)

                    candidates.append({
                        "candidate_pattern": re.escape(m.group(0)),
                        "example_context": problem_line.strip(),
                        "line": line_num + 1,
                        "reward_score": None
                    })
    except Exception:
        pass

    # 4️⃣ Library detection & vulnerability checks
    try:
        libs = detect_libraries_in_content(content, lang_key)
        for pkg in libs:
            pkg_key = pkg.lower()
            if pkg_key in LIB_VULN_DB:
                info = LIB_VULN_DB[pkg_key]
                finding = {
                    "type": f"Dependency: {pkg}",
                    "severity": info.get("severity", "Medium"),
                    "problem_line": f"Detected dependency reference to '{pkg}'",
                    "fix": info.get("fix", ""),
                    "line": None,
                    "ai_suggestion": info.get("advisory", "")
                }
                findings.append(finding)

                candidates.append({
                    "candidate_pattern": pkg,
                    "example_context": f"Detected library: {pkg}",
                    "line": None,
                    "reward_score": None
                })
    except Exception:
        pass

    # 5️⃣ Deduplicate findings and candidates
    seen_findings = set()
    deduped_findings = []
    for f in findings:
        key = (f.get("type"), f.get("line"), (f.get("problem_line") or "")[:200])
        if key in seen_findings:
            continue
        seen_findings.add(key)
        deduped_findings.append(f)

    seen_candidates = set()
    deduped_candidates = []
    for c in candidates:
        key = (c.get("candidate_pattern"), c.get("line"))
        if key in seen_candidates:
            continue
        seen_candidates.add(key)
        deduped_candidates.append(c)

    if not deduped_findings:
        deduped_findings = [{"note": "No obvious issues found."}]

    return deduped_findings, deduped_candidates

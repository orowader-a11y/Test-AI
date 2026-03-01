import json
import importlib.util
import os
import queue
import re
import shutil
import subprocess
import sys
import threading
import zipfile
import urllib.error
import urllib.request
from datetime import datetime
from dataclasses import dataclass
from pathlib import Path
from tkinter import END, DoubleVar, StringVar, Toplevel, Tk, filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText

CONFIG_FILE = "config.properties"
OUTPUT_DIR = Path("output")
LEARNING_FILE = Path("learning_memory.json")

STRICT_OUTPUT_EXAMPLE = {
    "overall_security_grade_percent": 72,
    "certainty_percent": 84,
    "files_analyzed": 37,
    "issues": [
        {
            "file": "src/utils/auth.js",
            "line_number": 48,
            "id": "ISSUE-014",
            "title": "JWT stored in localStorage",
            "severity": "High",
            "offending_code": "localStorage.setItem('token', jwt);",
            "why_this_is_a_problem": "Tokens in localStorage are accessible to XSS.",
            "suggested_fix": "Store JWT in HttpOnly, Secure cookies.",
        }
    ],
}

SYSTEM_PROMPT = (
    "You are a senior frontend security auditor. "
    "You must return strict JSON only, no markdown, no prose. "
    "Analyze recursively and correlate cross-file issues."
)

BOOTSTRAP_MARKER_FILE = Path(".bootstrap_examples_applied")
BOOTSTRAP_FEWSHOT_EXAMPLES = [
    {
        "file": "src/auth/session.js",
        "code": "localStorage.setItem('jwt', token);",
        "risk": "JWT token persisted in localStorage",
        "fix": "Use HttpOnly, Secure cookies and rotate short-lived access tokens.",
    },
    {
        "file": "src/chat/embed.ts",
        "code": "window.postMessage(payload, '*');",
        "risk": "Wildcard targetOrigin in postMessage",
        "fix": "Set explicit trusted origin and verify event.origin on receive.",
    },
    {
        "file": "src/profile/render.jsx",
        "code": "<div dangerouslySetInnerHTML={{ __html: userBio }} />",
        "risk": "Unsanitized HTML sink can enable XSS",
        "fix": "Avoid raw HTML or sanitize with DOMPurify before rendering.",
    },
    {
        "file": "src/config/client.ts",
        "code": "const STRIPE_SECRET = 'sk_live_1234567890123456';",
        "risk": "Hardcoded secret in frontend bundle",
        "fix": "Move secret server-side and expose only public non-sensitive keys.",
    },
    {
        "file": "src/nav/redirect.js",
        "code": "window.location.href = nextUrl;",
        "risk": "Open redirect sink",
        "fix": "Validate/allowlist redirect targets before navigation.",
    },
    {
        "file": "src/legacy/eval.js",
        "code": "const result = eval(userSuppliedRule);",
        "risk": "Dynamic code execution",
        "fix": "Replace eval/new Function with safe parser or explicit dispatch.",
    },
    {
        "file": "src/search/query.ts",
        "code": "resultsEl.innerHTML = resultHtml;",
        "risk": "Direct innerHTML assignment",
        "fix": "Use textContent or sanitize untrusted HTML.",
    },
    {
        "file": "src/session/cookie.js",
        "code": "document.cookie = `session=${token}; path=/`;",
        "risk": "Session token written via JS cookie",
        "fix": "Set session cookies from server with HttpOnly + Secure + SameSite.",
    },
    {
        "file": "src/router/redirect.ts",
        "code": "router.push(query.next);",
        "risk": "Unvalidated redirect target",
        "fix": "Restrict redirects to same-origin/allowlisted routes.",
    },
    {
        "file": "src/sanitize/unsafe.tsx",
        "code": "element.outerHTML = userGeneratedHtml;",
        "risk": "Unsafe HTML sink (outerHTML)",
        "fix": "Avoid HTML sinks or sanitize with strict allowlist sanitizer.",
    },
    {
        "file": "src/transport/ws.js",
        "code": "socket.send(JSON.stringify({ token }));",
        "risk": "Potential token exposure over client channel",
        "fix": "Avoid sending raw session tokens in client message payloads.",
    },
    {
        "file": "src/bootstrap/init.js",
        "code": "window.addEventListener('message', (e) => handle(e.data));",
        "risk": "postMessage receiver missing origin validation",
        "fix": "Verify `e.origin` against trusted origins before handling messages.",
    },
]

@dataclass
class AppConfig:
    # Local runtime configuration.
    local_provider: str
    local_model: str
    ollama_command: str
    ollama_path_hint: str
    temperature: float
    max_files: int
    max_bytes_per_file: int
    max_total_chars: int
    learning_examples: int
    openai_model: str
    openai_api_key_env: str
    openai_base_url: str
    claude_model: str
    claude_api_key_env: str
    claude_base_url: str


def app_base_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def load_properties(path: str) -> AppConfig:
    """Load app settings from config.properties into a typed configuration object."""
    values = {}
    with open(path, "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()

    return AppConfig(
        local_provider=values.get("local.provider", "ollama").lower(),
        local_model=values.get("local.model", "llama3.1:8b"),
        ollama_command=values.get("local.ollamaCommand", "ollama"),
        ollama_path_hint=values.get("local.ollamaPath", ""),
        temperature=float(values.get("local.temperature", "0.1")),
        max_files=int(values.get("analysis.maxFiles", "300")),
        max_bytes_per_file=int(values.get("analysis.maxBytesPerFile", "9000")),
        max_total_chars=int(values.get("analysis.maxTotalChars", "180000")),
        learning_examples=int(values.get("learning.maxExamples", "12")),
        openai_model=values.get("openai.model", "gpt-4o-mini"),
        openai_api_key_env=values.get("openai.apiKeyEnv", "OPENAI_API_KEY"),
        openai_base_url=values.get("openai.baseUrl", "https://api.openai.com/v1/chat/completions"),
        claude_model=values.get("claude.model", "claude-3-5-sonnet-20241022"),
        claude_api_key_env=values.get("claude.apiKeyEnv", "ANTHROPIC_API_KEY"),
        claude_base_url=values.get("claude.baseUrl", "https://api.anthropic.com/v1/messages"),
    )


def resolve_ollama_executable(config: AppConfig) -> str:
    candidates = []

    if config.ollama_path_hint:
        candidates.append(config.ollama_path_hint)

    candidates.append(config.ollama_command)

    which_cmd = shutil.which(config.ollama_command)
    if which_cmd:
        candidates.append(which_cmd)

    if os.name == "nt":
        localappdata = os.environ.get("LOCALAPPDATA", "")
        program_files = os.environ.get("ProgramFiles", "")
        candidates.extend(
            [
                str(Path(localappdata) / "Programs" / "Ollama" / "ollama.exe") if localappdata else "",
                str(Path(program_files) / "Ollama" / "ollama.exe") if program_files else "",
            ]
        )
    else:
        candidates.extend(["/usr/local/bin/ollama", "/usr/bin/ollama"])

    seen = set()
    for cand in candidates:
        cand = cand.strip()
        if not cand or cand in seen:
            continue
        seen.add(cand)

        if Path(cand).exists():
            return cand

        resolved = shutil.which(cand)
        if resolved:
            return resolved

    raise RuntimeError(
        "Could not resolve Ollama executable. Set local.ollamaPath in config.properties, "
        "or ensure ollama is on PATH for the launched app process."
    )


def guess_line_number(content: str, snippet: str) -> int:
    if not content or not snippet:
        return 1
    idx = content.find(snippet[:120])
    if idx < 0:
        return 1
    return content.count("\n", 0, idx) + 1


def summarize_zip(zip_path: Path, max_files: int, max_bytes_per_file: int, max_total_chars: int) -> dict:
    file_summaries = []
    total_chars = 0

    with zipfile.ZipFile(zip_path, "r") as archive:
        names = [name for name in archive.namelist() if not name.endswith("/")]
        for name in names[:max_files]:
            lower = name.lower()
            is_relevant = lower.endswith(
                (
                    ".js",
                    ".ts",
                    ".jsx",
                    ".tsx",
                    ".html",
                    ".css",
                    ".json",
                    "package.json",
                    "package-lock.json",
                    "yarn.lock",
                    "pnpm-lock.yaml",
                    "vite.config.js",
                    "webpack.config.js",
                    "next.config.js",
                    ".env",
                    ".env.local",
                )
            )

            entry = {
                "path": name,
                "size": archive.getinfo(name).file_size,
                "is_frontend_relevant": is_relevant,
                "content": "",
            }

            if is_relevant and total_chars < max_total_chars:
                try:
                    raw = archive.read(name)[:max_bytes_per_file]
                    decoded = raw.decode("utf-8", errors="replace")
                    budget = max_total_chars - total_chars
                    decoded = decoded[:budget]
                    entry["content"] = decoded
                    total_chars += len(decoded)
                except Exception as ex:
                    entry["content"] = f"<unreadable:{ex}>"

            file_summaries.append(entry)

    return {
        "zip_name": zip_path.name,
        "files_analyzed": len(file_summaries),
        "files": file_summaries,
        "cross_file_analysis_required": True,
        "required_checks": [
            "Exposed secrets / tokens",
            "API endpoint leaks",
            "Unsafe auth flows",
            "XSS sinks & injection vectors",
            "postMessage misuse",
            "CSP weaknesses",
            "Dangerous dependencies (heuristic if lockfile present)",
            "Insecure storage patterns",
            "Debug leftovers",
            "Build misconfigurations",
            "Public environment variable leaks",
            "Open redirects",
            "Prototype pollution vectors",
            "SSRF-enabling frontend patterns",
            "AI-generated insecure code patterns",
        ],
    }


def load_learning_memory() -> dict:
    if not LEARNING_FILE.exists():
        return {"entries": []}
    try:
        data = json.loads(LEARNING_FILE.read_text(encoding="utf-8"))
        if isinstance(data, dict) and isinstance(data.get("entries"), list):
            return data
    except Exception:
        pass
    return {"entries": []}


def save_learning_memory(memory: dict):
    LEARNING_FILE.write_text(json.dumps(memory, indent=2), encoding="utf-8")


def _extract_pattern(snippet: str) -> str:
    clean = (snippet or "").strip()
    if not clean:
        return ""
    if len(clean) > 120:
        clean = clean[:120]
    return clean


def build_learning_context(config: AppConfig) -> str:
    memory = load_learning_memory()
    entries = memory.get("entries", [])[-max(1, config.learning_examples) :]
    if not entries:
        return ""

    lines = ["Known historical findings (high signal examples):"]
    for item in entries:
        lines.append(
            f"- {item.get('title','Issue')} | severity={item.get('severity','Medium')} | "
            f"pattern={item.get('pattern','')} | why={item.get('why','')} | fix={item.get('fix','')}"
        )
    return "\n".join(lines)


def learn_from_result_pack(result_pack: list[dict]):
    memory = load_learning_memory()
    entries = memory.get("entries", [])
    seen = {(e.get("title", ""), e.get("pattern", "")) for e in entries}

    for pack in result_pack:
        for issue in pack.get("result", {}).get("issues", []):
            pattern = _extract_pattern(issue.get("offending_code", ""))
            key = (issue.get("title", ""), pattern)
            if key in seen:
                continue
            entries.append(
                {
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "title": issue.get("title", "Potential security issue"),
                    "severity": issue.get("severity", "Medium"),
                    "pattern": pattern,
                    "why": issue.get("why_this_is_a_problem", ""),
                    "fix": issue.get("suggested_fix", ""),
                }
            )
            seen.add(key)

    memory["entries"] = entries[-200:]
    save_learning_memory(memory)

def should_include_bootstrap_examples() -> bool:
    return not BOOTSTRAP_MARKER_FILE.exists()


def mark_bootstrap_examples_applied():
    try:
        BOOTSTRAP_MARKER_FILE.write_text(datetime.utcnow().isoformat() + "Z", encoding="utf-8")
    except Exception:
        pass


def build_bootstrap_context() -> str:
    if not should_include_bootstrap_examples():
        return ""

    lines = [
        "First-run training examples (obviously insecure frontend snippets):",
        "Use these as calibration signals when evaluating the uploaded ZIP.",
    ]
    for idx, item in enumerate(BOOTSTRAP_FEWSHOT_EXAMPLES, start=1):
        lines.append(
            f"EXAMPLE-{idx}: file={item['file']} | code={item['code']} | risk={item['risk']} | fix={item['fix']}"
        )
    return "\n".join(lines)


def parse_json_from_text(raw_text: str) -> dict:
    text = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", raw_text or "")
    text = text.replace("\r", "\n").strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    fence_match = re.search(r"```(?:json)?\s*(\{.*\})\s*```", text, flags=re.DOTALL)
    if fence_match:
        return json.loads(fence_match.group(1))

    decoder = json.JSONDecoder()
    for idx, char in enumerate(text):
        if char != "{":
            continue
        try:
            parsed, _end = decoder.raw_decode(text[idx:])
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            continue

    raise ValueError("Could not parse JSON from model output.")


def infer_severity_from_text(text: str) -> str:
    lowered = (text or "").lower()
    if any(token in lowered for token in ["rce", "critical", "account takeover", "secret", "token leak"]):
        return "High"
    if any(token in lowered for token in ["xss", "csrf", "redirect", "injection", "bypass"]):
        return "Medium"
    return "Low"


def build_fallback_result_from_text(raw_text: str, payload: dict) -> dict:
    lines = [line.strip(" -	") for line in (raw_text or "").splitlines() if line.strip()]
    issues = []
    marker = "potential security concerns"
    in_concerns = False

    for line in lines:
        lowered = line.lower()
        if marker in lowered:
            in_concerns = True
            continue
        if in_concerns and (line.startswith("To address") or line.startswith("Note:")):
            break

        match = re.match(r"^(?:\d+[\.)]\s*)?(?:\*\*)?(.+?)(?:\*\*)?:\s*(.*)$", line)
        if not match:
            continue

        title = match.group(1).strip()
        detail = match.group(2).strip() or "Potential issue inferred from model prose output."

        if in_concerns or any(key in lowered for key in ["concern", "risk", "xss", "secret", "token", "auth", "endpoint"]):
            issues.append(
                {
                    "file": "unknown",
                    "line_number": 1,
                    "id": f"ISSUE-{len(issues)+1:03d}",
                    "title": title[:120],
                    "severity": infer_severity_from_text(f"{title} {detail}"),
                    "offending_code": "",
                    "why_this_is_a_problem": detail,
                    "suggested_fix": "Review this finding in source context and apply secure coding controls.",
                }
            )

    result = {
        "overall_security_grade_percent": 0 if issues else 50,
        "certainty_percent": 35,
        "files_analyzed": int(payload.get("files_analyzed", 0)),
        "issues": issues,
    }
    return ensure_output_shape(result, payload)


def ensure_output_shape(result: dict, fallback_summary: dict) -> dict:
    out = {
        "overall_security_grade_percent": int(result.get("overall_security_grade_percent", 0)),
        "certainty_percent": int(result.get("certainty_percent", 0)),
        "files_analyzed": int(result.get("files_analyzed", fallback_summary.get("files_analyzed", 0))),
        "issues": [],
    }

    for idx, issue in enumerate(result.get("issues", []), start=1):
        out["issues"].append(
            {
                "file": str(issue.get("file", "unknown")),
                "line_number": int(issue.get("line_number", 1) or 1),
                "id": str(issue.get("id", f"ISSUE-{idx:03d}")),
                "title": str(issue.get("title", "Potential security issue")),
                "severity": str(issue.get("severity", "Medium")).title(),
                "offending_code": str(issue.get("offending_code", "")),
                "why_this_is_a_problem": str(issue.get("why_this_is_a_problem", "")),
                "suggested_fix": str(issue.get("suggested_fix", "")),
            }
        )

    return out


def resolve_issue_locations(result: dict, payload: dict) -> dict:
    file_content = {str(item.get("path", "")): str(item.get("content", "")) for item in payload.get("files", [])}
    candidates = list(file_content.items())

    resolved = []
    for issue in result.get("issues", []):
        cloned = dict(issue)
        file_name = str(cloned.get("file", "unknown")).strip()
        code = str(cloned.get("offending_code", "")).strip()
        why = str(cloned.get("why_this_is_a_problem", "")).strip()

        if (not file_name or file_name.lower() == "unknown") and code:
            match_path = ""
            for path, content in candidates:
                if code and code in content:
                    match_path = path
                    break
            if match_path:
                cloned["file"] = match_path
                cloned["line_number"] = guess_line_number(file_content.get(match_path, ""), code)

        if cloned.get("file", "unknown").lower() == "unknown" and not code and not why:
            continue

        resolved.append(cloned)

    result["issues"] = resolved
    return result


def _make_issue(file_path: str, line_number: int, idx: int, title: str, severity: str, code: str, why: str, fix: str) -> dict:
    return {
        "file": file_path,
        "line_number": max(1, int(line_number)),
        "id": f"ISSUE-{idx:03d}",
        "title": title,
        "severity": severity,
        "offending_code": code[:220],
        "why_this_is_a_problem": why,
        "suggested_fix": fix,
    }


def _tool_issue_key(issue: dict) -> tuple[str, int, str]:
    return (
        str(issue.get("file", "unknown")),
        max(1, int(issue.get("line_number", 1) or 1)),
        str(issue.get("title", "")).strip().lower(),
    )


def _normalize_issue_title(title: str) -> str:
    clean = (title or "").strip()
    clean = re.sub(r"^\[[^\]]+\]\s*", "", clean)
    clean = re.sub(r"^learned pattern match:\s*", "", clean, flags=re.IGNORECASE)
    return clean.strip()


def _issue_dedupe_key(issue: dict) -> tuple[str, int, str, str]:
    code = re.sub(r"\s+", " ", str(issue.get("offending_code", "")).strip().lower())
    return (
        str(issue.get("file", "unknown")).strip().lower(),
        max(1, int(issue.get("line_number", 1) or 1)),
        _normalize_issue_title(str(issue.get("title", "")).lower()),
        code[:140],
    )


def dedupe_issues(issues: list[dict]) -> list[dict]:
    deduped = []
    seen = set()
    for issue in issues:
        key = _issue_dedupe_key(issue)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(issue)
    return deduped


def annotate_source_issues(issues: list[dict], source_tag: str) -> list[dict]:
    tagged = []
    for issue in issues:
        cloned = dict(issue)
        if source_tag in {"chatgpt", "claude"}:
            cloned["title"] = f"[{source_tag}] {cloned.get('title', 'Potential security issue')}"
        tagged.append(cloned)
    return tagged


def _run_regex_tool(tool_name: str, payload: dict, patterns: list[tuple[re.Pattern, str, str, str, str]]) -> list[dict]:
    issues = []
    for item in payload.get("files", []):
        file_path = str(item.get("path", "unknown"))
        content = item.get("content") or ""
        if not content:
            continue
        for regex, title, severity, why, fix in patterns:
            for match in regex.finditer(content):
                line = content.count("\n", 0, match.start()) + 1
                code_line = content[match.start() : match.start() + 180].splitlines()[0].strip()
                issues.append(
                    _make_issue(
                        file_path,
                        line,
                        len(issues) + 1,
                        f"[{tool_name}] {title}",
                        severity,
                        code_line,
                        why,
                        fix,
                    )
                )
                if len(issues) >= 80:
                    return issues
    return issues


def run_internal_library_analyses(payload: dict) -> tuple[list[dict], list[str]]:
    tool_issues: list[dict] = []
    tools_used: list[str] = []

    tool_specs = []
    sonarqube_available = bool(importlib.util.find_spec("sonarqube")) or bool(shutil.which("sonar-scanner"))
    if sonarqube_available:
        sonarqube_patterns = [
            (re.compile(r"dangerouslySetInnerHTML", re.IGNORECASE), "Unsanitized HTML rendering sink", "High", "Sonar-style sink detection flagged raw HTML rendering path.", "Use safe DOM APIs or sanitize trusted HTML with an allowlist sanitizer."),
            (re.compile(r"window\.postMessage\([^\n]{0,200},\s*(?:\"|\')\*(?:\"|\')", re.IGNORECASE), "Wildcard postMessage target", "High", "Wildcard target origin may leak sensitive payloads to untrusted windows.", "Set explicit targetOrigin and validate event.origin on receiver side."),
            (re.compile(r"(?:location\.(?:href|assign|replace)\s*=|window\.open\()", re.IGNORECASE), "Potential open redirect", "Medium", "Navigation sinks should validate attacker-controlled URLs.", "Restrict redirects to same-origin or allowlisted destinations."),
        ]
        tool_specs.append(("sonarqube", sonarqube_patterns))

    dependency_patterns = [
        (re.compile(r'"(lodash|minimist|jquery|moment)"\s*:\s*"(?:\^|~)?[0-3]?\.?[0-9]*', re.IGNORECASE), "Potentially outdated frontend dependency", "Medium", "Outdated dependency signatures can indicate known vulnerable versions.", "Pin and upgrade dependency versions, then review CVEs in advisories."),
        (re.compile(r"npm install [^\n]*--force", re.IGNORECASE), "Forced dependency install command", "Low", "--force may bypass important package manager protections.", "Avoid force installs and resolve peer/dependency conflicts explicitly."),
    ]
    tool_specs.append(("dep-audit-py", dependency_patterns))

    dataflow_patterns = [
        (re.compile(r"(?:innerHTML|outerHTML)\s*=\s*[^\n;]+", re.IGNORECASE), "DOM injection sink", "Medium", "Dynamic HTML assignment can create XSS when data is attacker-controlled.", "Prefer textContent/DOM createElement patterns or sanitize before injection."),
        (re.compile(r"(?:localStorage|sessionStorage)\.setItem\([^\n]{0,150}(?:token|jwt|auth|session)", re.IGNORECASE), "Sensitive session artifact in web storage", "High", "Web storage is exposed to script context and XSS abuse.", "Use HttpOnly + Secure cookies and server session controls for sensitive tokens."),
        (re.compile(r"(?:eval\s*\(|new\s+Function\s*\()", re.IGNORECASE), "Dynamic code execution sink", "High", "Executing dynamic strings increases code injection risk.", "Replace dynamic execution with strict parsers or explicit command dispatch."),
    ]
    tool_specs.append(("frontend-sast-py", dataflow_patterns))

    secrets_patterns = [
        (re.compile(r"(?:api[_-]?key|secret|token)\s*[:=]\s*(?:\"|\')[A-Za-z0-9_\-]{16,}(?:\"|\')", re.IGNORECASE), "Hardcoded credential-like value", "Critical", "Credential-like string appears hardcoded in frontend-reachable code.", "Move secrets to backend and rotate exposed credentials immediately."),
        (re.compile(r"(?:AKIA[0-9A-Z]{16}|sk_live_[0-9A-Za-z]{10,})"), "Cloud/payment key pattern detected", "Critical", "Known secret prefix signature detected.", "Revoke and rotate keys; use secure secret management outside client bundles."),
    ]
    tool_specs.append(("secrets-py", secrets_patterns))

    selected_specs = tool_specs[:3]
    for tool_name, patterns in selected_specs:
        tool_issues.extend(_run_regex_tool(tool_name, payload, patterns))
        tools_used.append(tool_name)

    return tool_issues, tools_used


def learn_when_tools_outperform_model(model_result: dict, tool_issues: list[dict]) -> int:
    if not tool_issues:
        return 0
    model_keys = {_tool_issue_key(issue) for issue in model_result.get("issues", [])}
    missed = [issue for issue in tool_issues if _tool_issue_key(issue) not in model_keys]
    if not missed:
        return 0

    memory = load_learning_memory()
    entries = memory.get("entries", [])
    seen = {(e.get("title", ""), e.get("pattern", "")) for e in entries}

    for issue in missed:
        pattern = _extract_pattern(issue.get("offending_code", ""))
        title = issue.get("title", "Potential security issue")
        key = (title, pattern)
        if key in seen:
            continue
        entries.append(
            {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "title": title,
                "severity": issue.get("severity", "Medium"),
                "pattern": pattern,
                "why": issue.get("why_this_is_a_problem", ""),
                "fix": issue.get("suggested_fix", ""),
                "source": "tool_missed_by_model",
            }
        )
        seen.add(key)

    memory["entries"] = entries[-200:]
    save_learning_memory(memory)
    return len(missed)


def detect_static_security_issues(payload: dict, learning_entries: list[dict] | None = None) -> list[dict]:
    """Regex-based high-recall vulnerability sweep used alongside model output."""
    patterns = [
        (re.compile(r"localStorage\.setItem\([^\n]{0,120}(token|jwt|auth|session)", re.IGNORECASE), "Sensitive token stored in localStorage", "High", "Client-side storage is readable by injected scripts.", "Use HttpOnly, Secure cookies and short-lived server-managed sessions."),
        (re.compile(r'postMessage\([^\n]{0,200},\s*(?:"|\')\*(?:"|\')', re.IGNORECASE), "postMessage uses wildcard target origin", "High", "Using '*' as target origin can leak data to untrusted origins.", "Set an explicit trusted origin and validate message source/origin on receipt."),
        (re.compile(r"dangerouslySetInnerHTML", re.IGNORECASE), "dangerouslySetInnerHTML usage", "High", "Rendering raw HTML can introduce XSS if input is not strictly sanitized.", "Avoid raw HTML rendering or sanitize with a proven sanitizer (e.g. DOMPurify)."),
        (re.compile(r'(api[_-]?key|secret|token)\s*[:=]\s*(?:"|\')[A-Za-z0-9_\-]{16,}(?:"|\')', re.IGNORECASE), "Potential hardcoded secret/token", "Critical", "Hardcoded credentials can be extracted from bundles and abused.", "Move secrets server-side and inject only non-sensitive runtime config to frontend."),
        (re.compile(r"innerHTML\s*=", re.IGNORECASE), "Direct innerHTML assignment", "Medium", "Unsanitized HTML assignment is a common XSS sink.", "Use textContent or sanitize untrusted HTML before insertion."),
        (re.compile(r"location\.(href|assign|replace)\s*=", re.IGNORECASE), "Potential open redirect sink", "Medium", "Redirect destinations may be attacker-controlled if not validated.", "Allowlist destinations and reject external/untrusted redirect targets."),
        (re.compile(r"document\.cookie\s*=", re.IGNORECASE), "Client-side cookie write detected", "Medium", "Cookies set from JS cannot be HttpOnly and are exposed to XSS.", "Prefer server-set Secure/HttpOnly cookies for sensitive session tokens."),
        (re.compile(r"eval\s*\(|new\s+Function\s*\(", re.IGNORECASE), "Dynamic code execution pattern", "High", "eval/new Function can execute attacker-influenced code.", "Remove dynamic code execution and use safe parsing/dispatch mechanisms."),
        (re.compile(r"outerHTML\s*=", re.IGNORECASE), "Direct outerHTML assignment", "High", "outerHTML assignment is a powerful DOM injection sink.", "Avoid outerHTML for untrusted data; use safe DOM APIs."),
        (re.compile(r"window\.addEventListener\(\s*['\"]message['\"]", re.IGNORECASE), "postMessage listener detected", "Medium", "Message listeners must validate sender origin.", "Validate event.origin against explicit trusted origins before processing."),
        (re.compile(r"(fetch|axios\.|XMLHttpRequest)[^\n]{0,200}(http://)", re.IGNORECASE), "Insecure HTTP transport", "High", "Plain HTTP can leak sensitive traffic and tokens.", "Use HTTPS endpoints and enforce transport security."),
        (re.compile(r"(token|secret|api[_-]?key)[^\n]{0,120}(console\.log|alert)\(", re.IGNORECASE), "Sensitive value exposed to debug output", "Medium", "Logging secrets/tokens may expose credentials in logs/devtools.", "Remove sensitive debug logs and redact credentials."),
        (re.compile(r"(router\.push|navigate|location\.(href|assign|replace))\([^\n]{0,120}(next|redirect|returnUrl)", re.IGNORECASE), "Unvalidated redirect parameter", "Medium", "User-controlled redirect params can cause phishing/open-redirect paths.", "Allowlist redirect targets and block external destinations."),
        (re.compile(r"setTimeout\(\s*['\"]", re.IGNORECASE), "String-based setTimeout execution", "Medium", "String-based timers behave like eval and can execute unintended code.", "Pass function references instead of executable strings."),
        (re.compile(r"localStorage\.getItem\([^\n]{0,120}(token|jwt|auth|session)", re.IGNORECASE), "Sensitive token read from localStorage", "Medium", "Frequent token retrieval in script context increases XSS impact.", "Prefer server-managed sessions and avoid token persistence in JS-readable stores."),
        (re.compile(r"target=\"_blank\"", re.IGNORECASE), "target=_blank usage detected", "Low", "Without rel=noopener noreferrer this can expose window.opener risks.", "Add rel=\"noopener noreferrer\" to external links using target=_blank."),
        (re.compile(r"dangerouslySetInnerHTML\s*=\s*\{\{\s*__html:\s*[^}]+\}\}", re.IGNORECASE), "Raw HTML render path", "High", "Raw HTML render paths are high-risk when source data is not strongly sanitized.", "Use trusted markdown renderer/sanitizer and enforce strict allowlist."),
    ]

    issues = []
    seen = set()
    for item in payload.get("files", []):
        file_path = str(item.get("path", "unknown"))
        content = item.get("content") or ""
        if not content:
            continue

        for regex, title, severity, why, fix in patterns:
            for match in regex.finditer(content):
                line = content.count("\n", 0, match.start()) + 1
                code_line = content[match.start() : match.start() + 180].splitlines()[0].strip()
                issue = _make_issue(file_path, line, len(issues) + 1, title, severity, code_line, why, fix)
                key = _issue_dedupe_key(issue)
                if key in seen:
                    continue
                seen.add(key)
                issues.append(issue)
                if len(issues) >= 120:
                    return issues

    learning_entries = learning_entries or []
    for item in payload.get("files", []):
        file_path = str(item.get("path", "unknown"))
        content = item.get("content") or ""
        if not content:
            continue

        for learned in learning_entries:
            pattern = (learned.get("pattern") or "").strip()
            if not pattern or len(pattern) < 8:
                continue
            idx = content.find(pattern)
            if idx < 0:
                continue
            line = content.count("\n", 0, idx) + 1
            issue = _make_issue(
                file_path,
                line,
                len(issues) + 1,
                learned.get("title", "Historical finding"),
                learned.get("severity", "Medium"),
                pattern,
                learned.get("why", "Matched a previously observed risky pattern."),
                learned.get("fix", "Apply mitigation used for this known risky pattern."),
            )
            key = _issue_dedupe_key(issue)
            if key in seen:
                continue
            seen.add(key)
            issues.append(issue)
            if len(issues) >= 150:
                return issues

    return issues


def merge_and_score_results(
    model_result: dict,
    heuristic_issues: list[dict],
    tool_issues: list[dict],
    fallback_summary: dict,
    tools_used: list[str],
) -> dict:
    merged = ensure_output_shape(model_result, fallback_summary)

    combined = merged.get("issues", []) + heuristic_issues + tool_issues
    deduped = dedupe_issues(combined)

    normalized = []
    for idx, issue in enumerate(deduped, start=1):
        cloned = dict(issue)
        cloned["id"] = f"ISSUE-{idx:03d}"
        cloned["title"] = _normalize_issue_title(cloned.get("title", "Potential security issue"))
        normalized.append(cloned)
    merged["issues"] = normalized

    issue_count = len(merged["issues"])
    if issue_count:
        weights = {"Low": 1.0, "Medium": 2.2, "High": 3.8, "Critical": 5.0}
        weighted = sum(weights.get(i.get("severity", "Medium"), 2.2) for i in merged["issues"])
        grade_penalty = min(94, int(weighted * 2.7 + issue_count * 0.8))
        merged["overall_security_grade_percent"] = max(6, 100 - grade_penalty)
    else:
        merged["overall_security_grade_percent"] = 98

    model_issue_count = max(1, len(model_result.get("issues", [])))
    tool_issue_count = len(tool_issues)
    overlap = len({_issue_dedupe_key(i) for i in model_result.get("issues", [])} & {_issue_dedupe_key(i) for i in tool_issues})
    agreement_ratio = overlap / max(1, tool_issue_count)
    tool_coverage_ratio = min(1.0, tool_issue_count / max(1, issue_count))
    files_analyzed = int(fallback_summary.get("files_analyzed", 0) or 0)
    breadth = min(1.0, files_analyzed / 60)
    tool_depth = min(1.0, len(tools_used) / 3)
    certainty = int(35 + 20 * breadth + 20 * tool_depth + 15 * agreement_ratio + 10 * tool_coverage_ratio)
    if issue_count == 0:
        certainty = min(certainty, 72)
    merged["certainty_percent"] = max(35, min(99, certainty))

    return merged


def build_analysis_prompt(payload: dict, learning_context: str = "") -> str:
    return (
        "Analyze this uploaded frontend ZIP summary as a static security review. "
        "Apply cross-file reasoning. Return STRICT JSON exactly in this shape:\n"
        f"{json.dumps(STRICT_OUTPUT_EXAMPLE, indent=2)}\n"
        "Rules:\n"
        "1) Include every field exactly as named.\n"
        "2) severity must be one of Low/Medium/High/Critical.\n"
        "3) Include concrete offending_code snippets whenever possible.\n"
        "4) line_number should be best estimate from provided file content.\n"
        "4.1) file must be a real file path from ZIP_SUMMARY files; never output 'unknown' when code snippet maps to a file.\n"
        "5) No markdown, no comments, JSON only.\n"
        "6) Output must start with { and end with }.\n\n"
        "7) Prefer precision over quantity; skip low-confidence items without evidence snippet/location.\n\n"
        f"ZIP_SUMMARY:\n{json.dumps(payload)}\n\n"
        f"{learning_context}"
    )




def run_openai_chatgpt_analysis(config: AppConfig, prompt: str, payload: dict) -> dict | None:
    """Optional ChatGPT cross-check. Returns normalized strict-shape JSON or None."""
    api_key = os.environ.get(config.openai_api_key_env, "").strip()
    if not api_key:
        return None

    body = {
        "model": config.openai_model,
        "temperature": config.temperature,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        "response_format": {"type": "json_object"},
    }

    req = urllib.request.Request(
        config.openai_base_url,
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=90) as response:
            raw = response.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, TimeoutError, OSError):
        return None

    try:
        parsed = json.loads(raw)
        text = parsed["choices"][0]["message"]["content"]
        return ensure_output_shape(parse_json_from_text(text), payload)
    except Exception:
        return None


def run_claude_analysis(config: AppConfig, prompt: str, payload: dict) -> dict | None:
    """Optional Claude cross-check. Returns normalized strict-shape JSON or None."""
    api_key = os.environ.get(config.claude_api_key_env, "").strip()
    if not api_key:
        return None

    body = {
        "model": config.claude_model,
        "max_tokens": 2500,
        "temperature": config.temperature,
        "system": SYSTEM_PROMPT,
        "messages": [{"role": "user", "content": prompt}],
    }

    req = urllib.request.Request(
        config.claude_base_url,
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=90) as response:
            raw = response.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, TimeoutError, OSError):
        return None

    try:
        parsed = json.loads(raw)
        content = parsed.get("content", [])
        text = ""
        for part in content:
            if isinstance(part, dict) and part.get("type") == "text":
                text += part.get("text", "")
        if not text:
            return None
        return ensure_output_shape(parse_json_from_text(text), payload)
    except Exception:
        return None


def run_ollama_analysis(config: AppConfig, payload: dict, zip_path: Path | None = None) -> dict:
    learning_memory = load_learning_memory()
    learning_context = build_learning_context(config)
    bootstrap_context = build_bootstrap_context()
    combined_context = "\n\n".join(part for part in [learning_context, bootstrap_context] if part)
    analysis_prompt = build_analysis_prompt(payload, combined_context)
    prompt = f"{SYSTEM_PROMPT}\n\n{analysis_prompt}"
    ollama_exec = resolve_ollama_executable(config)

    env = os.environ.copy()
    if os.name == "nt":
        env["PATHEXT"] = env.get("PATHEXT", ".EXE;.BAT;.CMD")

    commands = [
        [ollama_exec, "run", config.local_model, "--format", "json"],
        [ollama_exec, "run", config.local_model],
    ]

    run_kwargs = {
        "input": prompt,
        "capture_output": True,
        "text": True,
        "encoding": "utf-8",
        "errors": "replace",
        "timeout": 600,
        "check": False,
        "cwd": str(app_base_dir()),
        "env": env,
    }
    if os.name == "nt" and hasattr(subprocess, "CREATE_NO_WINDOW"):
        run_kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW

    proc = None
    last_error = ""
    for idx, cmd in enumerate(commands):
        try:
            proc = subprocess.run(
                cmd,
                **run_kwargs,
            )
        except FileNotFoundError as ex:
            raise RuntimeError(
                "Ollama executable still could not be launched after path resolution. "
                "Set an absolute local.ollamaPath in config.properties, e.g. "
                "C:\\Users\\<you>\\AppData\\Local\\Programs\\Ollama\\ollama.exe"
            ) from ex

        if proc.returncode == 0:
            break

        stderr_out = (proc.stderr or "").lower()
        if idx == 0 and ("unknown flag" in stderr_out or "unknown shorthand flag" in stderr_out):
            continue

        last_error = proc.stderr.strip() or proc.stdout.strip()
        raise RuntimeError(f"Ollama failed ({proc.returncode}): {last_error}")

    if proc is None:
        raise RuntimeError(f"Ollama failed: {last_error or 'Unknown launch error.'}")

    try:
        parsed = parse_json_from_text(proc.stdout)
        model_result = ensure_output_shape(parsed, payload)
    except Exception:
        model_result = build_fallback_result_from_text(proc.stdout, payload)

    chatgpt_result = run_openai_chatgpt_analysis(config, analysis_prompt, payload)
    chatgpt_issues = annotate_source_issues(chatgpt_result.get("issues", []), "chatgpt") if chatgpt_result else []
    claude_result = run_claude_analysis(config, analysis_prompt, payload)
    claude_issues = annotate_source_issues(claude_result.get("issues", []), "claude") if claude_result else []

    heuristic_issues = detect_static_security_issues(payload, learning_memory.get("entries", []))
    tool_issues, tools_used = run_internal_library_analyses(payload)

    cross_llm_issues = dedupe_issues(chatgpt_issues + claude_issues)
    merged_model_issues = dedupe_issues(model_result.get("issues", []) + cross_llm_issues)
    merged_external_issues = dedupe_issues(tool_issues + cross_llm_issues)
    learn_when_tools_outperform_model(model_result, merged_external_issues)

    used_llms = ([] if not chatgpt_issues else ["chatgpt"]) + ([] if not claude_issues else ["claude"])
    fixed = merge_and_score_results(
        {**model_result, "issues": merged_model_issues},
        heuristic_issues,
        tool_issues + cross_llm_issues,
        payload,
        tools_used + used_llms,
    )
    fixed = resolve_issue_locations(fixed, payload)

    file_content = {item["path"]: item.get("content", "") for item in payload.get("files", [])}
    for issue in fixed["issues"]:
        if issue["line_number"] == 1 and issue["offending_code"] and issue["file"] in file_content:
            issue["line_number"] = guess_line_number(file_content[issue["file"]], issue["offending_code"])

    if bootstrap_context:
        mark_bootstrap_examples_applied()


    return fixed


def analyze_with_local_llm(config: AppConfig, payload: dict, zip_path: Path | None = None) -> dict:
    if config.local_provider == "ollama":
        return run_ollama_analysis(config, payload, zip_path)
    raise RuntimeError(f"Unsupported local.provider: {config.local_provider}")


class ZipSecurityApp:
    """Tk desktop app wrapper that orchestrates analysis, display, and fix-export workflows."""
    def __init__(self, root: Tk):
        self.root = root
        self.root.title("Frontend ZIP Security Analyzer")
        self.root.geometry("1250x760")
        self.root.configure(bg="#0f172a")

        self.selected_files: list[Path] = []
        self.result_queue: queue.Queue = queue.Queue()
        self.results_cache = []
        self.issue_lookup: dict[str, tuple[dict, str]] = {}
        self.selected_issue: dict | None = None
        self.selected_issue_zip: str = ""

        self.status = StringVar(value="Upload ZIP file(s) to run local-LLM frontend security analysis.")
        self.grade = StringVar(value="--")
        self.certainty = StringVar(value="--")
        self.files_count = StringVar(value="--")
        self.issue_count = StringVar(value="--")
        self.progress = DoubleVar(value=0.0)

        self._build_ui()
        self._poll_results()

    def _build_ui(self):
        style = ttk.Style()
        style.theme_use("clam")

        style.configure("Dark.TFrame", background="#eef3fb")
        style.configure("Card.TFrame", background="#ffffff")
        style.configure("CardTitle.TLabel", background="#ffffff", foreground="#5f6368", font=("Segoe UI", 10, "bold"))
        style.configure("Metric.TLabel", background="#ffffff", foreground="#202124", font=("Segoe UI", 16, "bold"))
        style.configure("Header.TLabel", background="#eef3fb", foreground="#1a73e8", font=("Segoe UI", 17, "bold"))
        style.configure("Sub.TLabel", background="#eef3fb", foreground="#5f6368", font=("Segoe UI", 10))
        style.configure("Bubble.TButton", background="#1a73e8", foreground="#ffffff", padding=(12, 8), borderwidth=0)
        style.map("Bubble.TButton", background=[("active", "#1967d2")])
        style.configure("Horizontal.TProgressbar", background="#1a73e8", troughcolor="#e0e7f0", bordercolor="#e0e7f0", lightcolor="#1a73e8", darkcolor="#1557b0", thickness=12)

        container = ttk.Frame(self.root, style="Dark.TFrame", padding=14)
        container.pack(fill="both", expand=True)

        header = ttk.Frame(container, style="Dark.TFrame")
        header.pack(fill="x")
        ttk.Label(header, text="Frontend Security Dashboard", style="Header.TLabel").pack(anchor="w")
        ttk.Label(
            header,
            text="Local LLM + static checks. Upload ZIPs, inspect findings, export machine JSON and human report.",
            style="Sub.TLabel",
        ).pack(anchor="w", pady=(4, 10))

        metrics_row = ttk.Frame(container, style="Dark.TFrame")
        metrics_row.pack(fill="x", pady=(0, 10))

        self._metric_card(metrics_row, "Security Grade", self.grade).pack(side="left", fill="x", expand=True, padx=(0, 8))
        self._metric_card(metrics_row, "Certainty", self.certainty).pack(side="left", fill="x", expand=True, padx=(0, 8))
        self._metric_card(metrics_row, "Files", self.files_count).pack(side="left", fill="x", expand=True, padx=(0, 8))
        self._metric_card(metrics_row, "Issues", self.issue_count).pack(side="left", fill="x", expand=True)

        controls = ttk.Frame(container, style="Dark.TFrame")
        controls.pack(fill="x", pady=(0, 10))
        ttk.Button(controls, text="Upload ZIP Files", style="Bubble.TButton", command=self.select_files).pack(side="left")
        ttk.Button(controls, text="Run Local Analysis", style="Bubble.TButton", command=self.run_analysis).pack(side="left", padx=8)
        ttk.Button(controls, text="Configure Providers", style="Bubble.TButton", command=self.open_config_window).pack(side="left", padx=8)
        ttk.Button(controls, text="Export Visible JSON", style="Bubble.TButton", command=self.save_output).pack(side="left")
        ttk.Label(controls, textvariable=self.status, style="Sub.TLabel").pack(side="left", padx=12)

        self.progress_bar = ttk.Progressbar(container, mode="determinate", variable=self.progress, maximum=100)
        self.progress_bar.pack(fill="x", pady=(0, 10))

        main = ttk.Panedwindow(container, orient="horizontal")
        main.pack(fill="both", expand=True)

        left = ttk.Frame(main, style="Card.TFrame", padding=12)
        right = ttk.Frame(main, style="Card.TFrame", padding=12)
        main.add(left, weight=1)
        main.add(right, weight=3)

        ttk.Label(left, text="Selected ZIP Files", style="CardTitle.TLabel").pack(anchor="w")
        self.file_list = ScrolledText(left, bg="#f8f9fa", fg="#202124", insertbackground="#202124", height=14, relief="flat", wrap="none")
        self.file_list.pack(fill="both", expand=True, pady=(6, 0))

        ttk.Label(right, text="Findings", style="CardTitle.TLabel").pack(anchor="w")
        cols = ("id", "severity", "file", "line", "title")
        self.issues_tree = ttk.Treeview(right, columns=cols, show="headings", height=12)
        for col, width in [("id", 90), ("severity", 90), ("file", 260), ("line", 70), ("title", 380)]:
            self.issues_tree.heading(col, text=col.upper())
            self.issues_tree.column(col, width=width, anchor="w")
        self.issues_tree.tag_configure("critical", background="#b91c1c", foreground="white")
        self.issues_tree.tag_configure("high", background="#dc2626", foreground="white")
        self.issues_tree.tag_configure("medium", background="#ea580c", foreground="white")
        self.issues_tree.tag_configure("low", background="#eab308", foreground="#1f2937")
        self.issues_tree.pack(fill="x", pady=(6, 8))
        self.issues_tree.bind("<<TreeviewSelect>>", self._on_issue_selected)

        details_header = ttk.Frame(right, style="Card.TFrame")
        details_header.pack(fill="x")
        ttk.Label(details_header, text="Issue Details", style="CardTitle.TLabel").pack(side="left", anchor="w")
        self.fix_button = ttk.Button(details_header, text="Generate Fixed File", style="Bubble.TButton", command=self.generate_fix_for_selected_issue)
        self.fix_button.pack(side="right")
        self.fix_button.state(["disabled"])
        self.issue_details = ScrolledText(
            right,
            bg="#ffffff",
            fg="#202124",
            insertbackground="#202124",
            height=14,
            relief="flat",
            wrap="word",
            font=("Segoe UI", 10),
        )
        self.issue_details.pack(fill="both", expand=True, pady=(6, 8))
        self.issue_details.tag_configure("title", font=("Segoe UI", 12, "bold"), foreground="#1a73e8")
        self.issue_details.tag_configure("section", font=("Segoe UI", 10, "bold"), foreground="#5f6368")
        self.issue_details.tag_configure("body", font=("Segoe UI", 10), foreground="#202124")
        self.issue_details.tag_configure("meta", font=("Segoe UI", 9), foreground="#5f6368")
        self.issue_details.tag_configure("code", font=("Consolas", 9), foreground="#202124", background="#eef3fb")

    def _metric_card(self, parent, title: str, value_var: StringVar):
        frame = ttk.Frame(parent, style="Card.TFrame", padding=10)
        ttk.Label(frame, text=title, style="CardTitle.TLabel").pack(anchor="w")
        ttk.Label(frame, textvariable=value_var, style="Metric.TLabel").pack(anchor="w", pady=(6, 0))
        return frame

    def select_files(self):
        files = filedialog.askopenfilenames(filetypes=[("ZIP files", "*.zip")])
        if not files:
            return
        self.selected_files = [Path(file) for file in files]
        self.file_list.delete("1.0", END)
        for file in self.selected_files:
            self.file_list.insert(END, f"{file}\n")
        self.status.set(f"Loaded {len(self.selected_files)} ZIP file(s).")

    def run_analysis(self):
        """Start async analysis and reset visible outputs/progress state."""
        if not self.selected_files:
            messagebox.showwarning("No files selected", "Please upload at least one ZIP file.")
            return

        if not Path(CONFIG_FILE).exists():
            messagebox.showerror("Missing config", f"{CONFIG_FILE} was not found.")
            return

        config = load_properties(CONFIG_FILE)
        chatgpt_enabled = bool(os.environ.get(config.openai_api_key_env, "").strip())
        claude_enabled = bool(os.environ.get(config.claude_api_key_env, "").strip())
        extras = []
        if chatgpt_enabled:
            extras.append("chatgpt")
        if claude_enabled:
            extras.append("claude")
        suffix = " + " + ",".join(extras) if extras else ""
        mode_label = f"{config.local_provider}:{config.local_model}" + suffix
        self.status.set(f"Running local analysis via {mode_label}...")
        self.issue_details.delete("1.0", END)
        self.progress.set(0)
        self._clear_findings_table()
        threading.Thread(target=self._analyze_worker, args=(config,), daemon=True).start()

    def _analyze_worker(self, config: AppConfig):
        """Background worker: analyze each ZIP, emit progress, and return aggregate payload."""
        OUTPUT_DIR.mkdir(exist_ok=True)
        aggregate = []
        try:
            total = max(1, len(self.selected_files))
            for idx, zip_path in enumerate(self.selected_files, start=1):
                # Progress slice for this file: 0-15% summarize, 15-95% model, 95-100% finalize
                slice_start = ((idx - 1) / total) * 95
                slice_end = (idx / total) * 95
                self.result_queue.put(("progress", {"percent": slice_start, "message": f"Summarizing {zip_path.name}..."}))
                summary = summarize_zip(
                    zip_path,
                    config.max_files,
                    config.max_bytes_per_file,
                    config.max_total_chars,
                )
                self.result_queue.put(("progress", {"percent": slice_start + (slice_end - slice_start) * 0.15, "message": f"Running model analysis for {zip_path.name}..."}))
                result = analyze_with_local_llm(config, summary, zip_path)
                outfile = OUTPUT_DIR / f"{zip_path.stem}.analysis.json"
                outfile.write_text(json.dumps(result, indent=2), encoding="utf-8")
                aggregate.append({"zip": str(zip_path), "output_json": str(outfile), "result": result})
                self.result_queue.put(("progress", {"percent": slice_end, "message": f"Completed {zip_path.name}"}))
            self.result_queue.put(("progress", {"percent": 100, "message": "Done."}))
            self.result_queue.put(("ok", aggregate))
        except Exception as ex:
            self.result_queue.put(("err", str(ex)))

    def _clear_findings_table(self):
        """Clear current issue rows/details before a new scan or refresh."""
        for row in self.issues_tree.get_children():
            self.issues_tree.delete(row)
        self.issue_details.delete("1.0", END)
        self.fix_button.state(["disabled"])
        self.selected_issue = None
        self.selected_issue_zip = ""

    def _severity_sort_key(self, issue: dict) -> int:
        """Order: Critical=0, High=1, Medium=2, Low=3 (most severe first)."""
        order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        return order.get(str(issue.get("severity", "Medium")).title(), 2)

    def _severity_tag(self, issue: dict) -> str:
        """Tag name for Treeview row styling (critical, high, medium, low)."""
        sev = str(issue.get("severity", "Medium")).title()
        if sev not in ("Critical", "High", "Medium", "Low"):
            return "medium"
        return sev.lower()

    def _refresh_dashboard(self, aggregate_results: list[dict]):
        if not aggregate_results:
            return

        first = aggregate_results[0]["result"]
        # Collect (issue, zip_path) then sort by severity (Critical first, then High, Medium, Low)
        flat = []
        for item in aggregate_results:
            zip_path = str(item.get("zip", ""))
            for issue in item["result"].get("issues", []):
                flat.append((issue, zip_path))
        flat.sort(key=lambda x: self._severity_sort_key(x[0]))

        self.issue_lookup = {}
        for row_index, (issue, zip_path) in enumerate(flat, start=1):
            key = f"issue-{row_index}"
            self.issue_lookup[key] = (issue, zip_path)

        self.grade.set(f"{first.get('overall_security_grade_percent', 0)}%")
        self.certainty.set(f"{first.get('certainty_percent', 0)}%")
        self.files_count.set(str(sum(item["result"].get("files_analyzed", 0) for item in aggregate_results)))
        self.issue_count.set(str(len(flat)))

        self._clear_findings_table()
        for row_index, (issue, zip_path) in enumerate(flat, start=1):
            key = f"issue-{row_index}"
            tag = self._severity_tag(issue)
            self.issues_tree.insert(
                "",
                END,
                iid=key,
                values=(
                    issue.get("id", ""),
                    issue.get("severity", ""),
                    issue.get("file", ""),
                    issue.get("line_number", ""),
                    issue.get("title", ""),
                ),
                tags=(tag,),
            )

    def _on_issue_selected(self, _event=None):
        selected = self.issues_tree.selection()
        if not selected:
            return
        iid = selected[0]
        values = self.issues_tree.item(iid, "values")
        if not values:
            return
        issue_info = self.issue_lookup.get(iid)
        if not issue_info:
            return
        issue, issue_zip = issue_info
        self.selected_issue = issue
        self.selected_issue_zip = issue_zip

        self.issue_details.delete("1.0", END)
        title = issue.get("title", "")
        self.issue_details.insert(END, title + "\n", "title")
        self.issue_details.insert(END, f"{issue.get('id', '')}  ·  {issue.get('severity', '')}  ·  {issue.get('file', '')}:{issue.get('line_number', '')}\n\n", "meta")
        self.issue_details.insert(END, "Why this matters\n", "section")
        self.issue_details.insert(END, (issue.get("why_this_is_a_problem") or "—") + "\n\n", "body")
        self.issue_details.insert(END, "Recommended fix\n", "section")
        self.issue_details.insert(END, (issue.get("suggested_fix") or "—") + "\n\n", "body")
        self.issue_details.insert(END, "Offending code\n", "section")
        code = (issue.get("offending_code") or "—").strip()
        self.issue_details.insert(END, code if code else "—", "code")
        if self.can_generate_fix(issue):
            self.fix_button.state(["!disabled"])
        else:
            self.fix_button.state(["disabled"])

    def _poll_results(self):
        try:
            status, payload = self.result_queue.get_nowait()
            if status == "progress":
                self.progress.set(float(payload.get("percent", 0)))
                self.status.set(payload.get("message", "Analyzing..."))
                self.root.after(250, self._poll_results)
                return
            if status == "ok":
                self.results_cache = payload
                self.status.set("Analysis complete.")
                self.progress.set(100)
                self._refresh_dashboard(payload)
                learn_from_result_pack(payload)
            else:
                self.status.set("Analysis failed.")
                self.progress.set(0)
                messagebox.showerror("Analysis failed", payload)
        except queue.Empty:
            pass
        self.root.after(250, self._poll_results)

    def can_generate_fix(self, issue: dict) -> bool:
        """Return True when the selected issue type has a deterministic auto-fix strategy."""
        title = str(issue.get("title", "")).lower()
        code = str(issue.get("offending_code", ""))
        if "innerhtml" in title or "outerhtml" in title:
            return True
        if "postmessage" in title and "*" in code:
            return True
        if "target=_blank" in title or "target=\"_blank\"" in code:
            return True
        if "eval" in title or "new function" in title:
            return True
        return False

    def apply_fix_to_content(self, content: str, issue: dict) -> str | None:
        """Apply narrow, safe-by-default code transforms for fixable issue categories."""
        title = str(issue.get("title", "")).lower()
        code = str(issue.get("offending_code", ""))

        if "innerhtml" in title:
            return content.replace("innerHTML", "textContent")
        if "outerhtml" in title:
            return content.replace("outerHTML", "textContent")
        if "postmessage" in title and "*" in code:
            return content.replace(", '*'", ", window.location.origin").replace(', "*"', ", window.location.origin")
        if "target=_blank" in title or 'target="_blank"' in code:
            return content.replace('target="_blank"', 'target="_blank" rel="noopener noreferrer"')
        if "eval" in title or "new function" in title:
            return content.replace("eval(", "/* FIX_REQUIRED: removed eval */ (")
        return None

    def generate_fix_for_selected_issue(self):
        """Generate a patched file for the selected issue when a deterministic fix exists."""
        issue = self.selected_issue
        zip_path = self.selected_issue_zip
        if not issue or not zip_path:
            messagebox.showinfo("No issue selected", "Select an issue with an available fix first.")
            return
        if not self.can_generate_fix(issue):
            messagebox.showinfo("Fix unavailable", "No deterministic auto-fix is available for this issue type.")
            return

        file_path = str(issue.get("file", "")).strip()
        if not file_path:
            messagebox.showwarning("Missing file", "This issue has no file path and cannot be auto-fixed.")
            return

        try:
            with zipfile.ZipFile(zip_path, "r") as archive:
                raw = archive.read(file_path)
            original = raw.decode("utf-8", errors="replace")
        except Exception as ex:
            messagebox.showerror("Fix generation failed", f"Could not read source file from ZIP: {ex}")
            return

        fixed = self.apply_fix_to_content(original, issue)
        if not fixed or fixed == original:
            messagebox.showinfo("No change", "Could not safely generate a changed file for this issue.")
            return

        zip_stem = Path(zip_path).stem
        out_file = OUTPUT_DIR / "fixed" / zip_stem / file_path
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_text(fixed, encoding="utf-8")
        messagebox.showinfo("Fixed file generated", f"Saved: {out_file}")

    def open_config_window(self):
        """Open a lightweight config editor for provider settings and persist to config.properties."""
        config = load_properties(CONFIG_FILE)
        win = Toplevel(self.root)
        win.title("Configure Providers")
        win.geometry("700x420")

        fields = [
            ("local.model", config.local_model),
            ("local.ollamaCommand", config.ollama_command),
            ("local.ollamaPath", config.ollama_path_hint),
            ("openai.model", config.openai_model),
            ("openai.apiKeyEnv", config.openai_api_key_env),
            ("openai.baseUrl", config.openai_base_url),
            ("claude.model", config.claude_model),
            ("claude.apiKeyEnv", config.claude_api_key_env),
            ("claude.baseUrl", config.claude_base_url),
        ]
        vars_map: dict[str, StringVar] = {}
        body = ttk.Frame(win, padding=12)
        body.pack(fill="both", expand=True)
        for i, (k, v) in enumerate(fields):
            ttk.Label(body, text=k).grid(row=i, column=0, sticky="w", pady=4)
            var = StringVar(value=str(v))
            vars_map[k] = var
            ttk.Entry(body, textvariable=var, width=70).grid(row=i, column=1, sticky="ew", pady=4)
        body.columnconfigure(1, weight=1)

        def save_config():
            lines = Path(CONFIG_FILE).read_text(encoding="utf-8").splitlines()
            updates = {k: vars_map[k].get() for k, _ in fields}
            out_lines = []
            for line in lines:
                stripped = line.strip()
                if not stripped or stripped.startswith("#") or "=" not in stripped:
                    out_lines.append(line)
                    continue
                key, _ = stripped.split("=", 1)
                key = key.strip()
                if key in updates:
                    out_lines.append(f"{key}={updates[key]}")
                else:
                    out_lines.append(line)
            Path(CONFIG_FILE).write_text("\n".join(out_lines) + "\n", encoding="utf-8")
            messagebox.showinfo("Saved", "Configuration updated.")
            win.destroy()

        ttk.Button(body, text="Save", style="Bubble.TButton", command=save_config).grid(row=len(fields) + 1, column=1, sticky="e", pady=10)

    def save_output(self):
        if not self.results_cache:
            messagebox.showinfo("No output", "Run an analysis first to export JSON.")
            return
        save_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")])
        if not save_path:
            return
        content = json.dumps(self.results_cache, indent=2)
        Path(save_path).write_text(content, encoding="utf-8")
        messagebox.showinfo("Saved", f"Saved JSON to {save_path}")


if __name__ == "__main__":
    root = Tk()
    ZipSecurityApp(root)
    root.mainloop()

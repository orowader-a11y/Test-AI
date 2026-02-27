import json
import os
import queue
import threading
import zipfile
from dataclasses import dataclass
from pathlib import Path
from tkinter import END, StringVar, Text, Tk, filedialog, messagebox, ttk
from urllib import error, request

CONFIG_FILE = "config.properties"
OUTPUT_DIR = Path("output")

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
            "suggested_fix": "Store JWT in HttpOnly, Secure cookies."
        }
    ]
}

SYSTEM_PROMPT = (
    "You are a senior frontend security auditor. "
    "You must return strict JSON only, no markdown, no prose. "
    "Analyze recursively and correlate cross-file issues."
)


@dataclass
class AppConfig:
    api_key: str
    model: str
    api_base: str
    temperature: float
    max_files: int
    max_bytes_per_file: int


def load_properties(path: str) -> AppConfig:
    values = {}
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()

    return AppConfig(
        api_key=values.get("openai.apiKey", ""),
        model=values.get("openai.model", "gpt-4.1-mini"),
        api_base=values.get("openai.apiBase", "https://api.openai.com/v1"),
        temperature=float(values.get("openai.temperature", "0.1")),
        max_files=int(values.get("analysis.maxFiles", "300")),
        max_bytes_per_file=int(values.get("analysis.maxBytesPerFile", "9000")),
    )


def guess_line_number(content: str, snippet: str) -> int:
    if not content or not snippet:
        return 1
    idx = content.find(snippet[:120])
    if idx < 0:
        return 1
    return content.count("\n", 0, idx) + 1


def summarize_zip(zip_path: Path, max_files: int, max_bytes_per_file: int) -> dict:
    file_summaries = []
    with zipfile.ZipFile(zip_path, "r") as archive:
        names = [n for n in archive.namelist() if not n.endswith("/")]
        for name in names[:max_files]:
            lower = name.lower()
            entry = {
                "path": name,
                "size": archive.getinfo(name).file_size,
                "is_frontend_relevant": lower.endswith(
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
                    )
                ),
                "content": "",
            }
            if entry["is_frontend_relevant"]:
                try:
                    raw = archive.read(name)[:max_bytes_per_file]
                    entry["content"] = raw.decode("utf-8", errors="replace")
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


def ensure_output_shape(result: dict, fallback_summary: dict) -> dict:
    out = {
        "overall_security_grade_percent": int(result.get("overall_security_grade_percent", 0)),
        "certainty_percent": int(result.get("certainty_percent", 0)),
        "files_analyzed": int(result.get("files_analyzed", fallback_summary.get("files_analyzed", 0))),
        "issues": [],
    }

    for idx, issue in enumerate(result.get("issues", []), start=1):
        normalized = {
            "file": str(issue.get("file", "unknown")),
            "line_number": int(issue.get("line_number", 1) or 1),
            "id": str(issue.get("id", f"ISSUE-{idx:03d}")),
            "title": str(issue.get("title", "Potential security issue")),
            "severity": str(issue.get("severity", "Medium")).title(),
            "offending_code": str(issue.get("offending_code", "")),
            "why_this_is_a_problem": str(issue.get("why_this_is_a_problem", "")),
            "suggested_fix": str(issue.get("suggested_fix", "")),
        }
        out["issues"].append(normalized)

    return out


def call_openai_analysis(config: AppConfig, payload: dict) -> dict:
    user_prompt = (
        "Analyze this uploaded frontend ZIP summary as a security review. "
        "Apply cross-file reasoning. Return STRICT JSON exactly in this shape:\n"
        f"{json.dumps(STRICT_OUTPUT_EXAMPLE, indent=2)}\n"
        "Rules:\n"
        "1) Include every field exactly as named.\n"
        "2) severities should be one of Low/Medium/High/Critical.\n"
        "3) Include concrete offending_code snippets when possible.\n"
        "4) line_number should be best estimate based on provided file content.\n"
        "5) No markdown code fences. JSON only."
    )

    body = {
        "model": config.model,
        "temperature": config.temperature,
        "response_format": {"type": "json_object"},
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
            {"role": "user", "content": json.dumps(payload)},
        ],
    }

    endpoint = config.api_base.rstrip("/") + "/chat/completions"
    req = request.Request(endpoint, data=json.dumps(body).encode("utf-8"), method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Authorization", f"Bearer {config.api_key}")

    try:
        with request.urlopen(req, timeout=180) as resp:
            model_response = json.loads(resp.read().decode("utf-8"))
    except error.HTTPError as ex:
        details = ex.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"OpenAI API error: {ex.code} {details}") from ex

    content = model_response["choices"][0]["message"]["content"]
    try:
        parsed = json.loads(content)
    except json.JSONDecodeError as ex:
        raise RuntimeError(f"Model did not return valid strict JSON. Raw: {content[:700]}") from ex

    fixed = ensure_output_shape(parsed, payload)
    file_content = {item["path"]: item.get("content", "") for item in payload.get("files", [])}
    for issue in fixed["issues"]:
        if issue["line_number"] == 1 and issue["offending_code"] and issue["file"] in file_content:
            issue["line_number"] = guess_line_number(file_content[issue["file"]], issue["offending_code"])

    return fixed


class ZipSecurityApp:
    def __init__(self, root: Tk):
        self.root = root
        self.root.title("Frontend ZIP Security Analyzer")
        self.root.geometry("1100x720")

        self.selected_files = []
        self.result_queue = queue.Queue()
        self.status = StringVar(value="Upload ZIP file(s) to run frontend security analysis.")

        self._build_ui()
        self._poll_results()

    def _build_ui(self):
        controls = ttk.Frame(self.root, padding=10)
        controls.pack(fill="x")

        ttk.Button(controls, text="Upload ZIP files", command=self.select_files).pack(side="left")
        ttk.Button(controls, text="Run Security Analysis", command=self.run_analysis).pack(side="left", padx=8)
        ttk.Button(controls, text="Save Output JSON", command=self.save_output).pack(side="left")
        ttk.Label(controls, textvariable=self.status).pack(side="left", padx=12)

        main = ttk.Panedwindow(self.root, orient="horizontal")
        main.pack(fill="both", expand=True, padx=10, pady=10)

        left = ttk.Frame(main, padding=5)
        right = ttk.Frame(main, padding=5)
        main.add(left, weight=1)
        main.add(right, weight=3)

        ttk.Label(left, text="Selected ZIP Files").pack(anchor="w")
        self.file_list = Text(left, width=38)
        self.file_list.pack(fill="both", expand=True)

        ttk.Label(right, text="Strict JSON Output").pack(anchor="w")
        self.output = Text(right)
        self.output.pack(fill="both", expand=True)

    def select_files(self):
        files = filedialog.askopenfilenames(filetypes=[("ZIP files", "*.zip")])
        if not files:
            return
        self.selected_files = [Path(f) for f in files]
        self.file_list.delete("1.0", END)
        for path in self.selected_files:
            self.file_list.insert(END, f"{path}\n")
        self.status.set(f"Loaded {len(self.selected_files)} ZIP file(s).")

    def run_analysis(self):
        if not self.selected_files:
            messagebox.showwarning("No files selected", "Please upload at least one ZIP.")
            return

        if not Path(CONFIG_FILE).exists():
            messagebox.showerror("Missing config", f"{CONFIG_FILE} not found.")
            return

        config = load_properties(CONFIG_FILE)
        if not config.api_key:
            messagebox.showerror("Missing API key", "Set openai.apiKey in config.properties")
            return

        self.output.delete("1.0", END)
        self.status.set("Analyzing ZIP(s) with ChatGPT API...")
        threading.Thread(target=self._analyze_worker, args=(config,), daemon=True).start()

    def _analyze_worker(self, config: AppConfig):
        OUTPUT_DIR.mkdir(exist_ok=True)
        aggregate = []
        try:
            for zip_path in self.selected_files:
                summary = summarize_zip(zip_path, config.max_files, config.max_bytes_per_file)
                result = call_openai_analysis(config, summary)
                outfile = OUTPUT_DIR / f"{zip_path.stem}.analysis.json"
                outfile.write_text(json.dumps(result, indent=2), encoding="utf-8")
                aggregate.append({
                    "zip": str(zip_path),
                    "output_json": str(outfile),
                    "result": result,
                })
            self.result_queue.put(("ok", aggregate))
        except Exception as ex:
            self.result_queue.put(("err", str(ex)))

    def _poll_results(self):
        try:
            status, payload = self.result_queue.get_nowait()
            if status == "ok":
                self.status.set("Analysis complete.")
                self.output.insert(END, json.dumps(payload, indent=2))
            else:
                self.status.set("Analysis failed.")
                self.output.insert(END, payload)
        except queue.Empty:
            pass
        self.root.after(250, self._poll_results)

    def save_output(self):
        content = self.output.get("1.0", END).strip()
        if not content:
            messagebox.showinfo("No output", "No JSON is currently visible.")
            return

        save_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")])
        if not save_path:
            return

        Path(save_path).write_text(content, encoding="utf-8")
        messagebox.showinfo("Saved", f"Saved JSON to {save_path}")


if __name__ == "__main__":
    root = Tk()
    try:
        ttk.Style().theme_use("clam")
    except Exception:
        pass
    ZipSecurityApp(root)
    root.mainloop()

import json
import queue
import re
import subprocess
import threading
import zipfile
from dataclasses import dataclass
from pathlib import Path
from tkinter import END, StringVar, Text, Tk, filedialog, messagebox, ttk

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
            "suggested_fix": "Store JWT in HttpOnly, Secure cookies.",
        }
    ],
}

SYSTEM_PROMPT = (
    "You are a senior frontend security auditor. "
    "You must return strict JSON only, no markdown, no prose. "
    "Analyze recursively and correlate cross-file issues."
)


@dataclass
class AppConfig:
    local_provider: str
    local_model: str
    ollama_command: str
    temperature: float
    max_files: int
    max_bytes_per_file: int
    max_total_chars: int


def load_properties(path: str) -> AppConfig:
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
        temperature=float(values.get("local.temperature", "0.1")),
        max_files=int(values.get("analysis.maxFiles", "300")),
        max_bytes_per_file=int(values.get("analysis.maxBytesPerFile", "9000")),
        max_total_chars=int(values.get("analysis.maxTotalChars", "180000")),
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


def parse_json_from_text(raw_text: str) -> dict:
    text = raw_text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    fence_match = re.search(r"```(?:json)?\s*(\{.*\})\s*```", text, flags=re.DOTALL)
    if fence_match:
        return json.loads(fence_match.group(1))

    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end > start:
        return json.loads(text[start : end + 1])

    raise ValueError("Could not parse JSON from model output.")


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


def build_analysis_prompt(payload: dict) -> str:
    return (
        "Analyze this uploaded frontend ZIP summary as a static security review. "
        "Apply cross-file reasoning. Return STRICT JSON exactly in this shape:\n"
        f"{json.dumps(STRICT_OUTPUT_EXAMPLE, indent=2)}\n"
        "Rules:\n"
        "1) Include every field exactly as named.\n"
        "2) severity must be one of Low/Medium/High/Critical.\n"
        "3) Include concrete offending_code snippets whenever possible.\n"
        "4) line_number should be best estimate from provided file content.\n"
        "5) No markdown, no comments, JSON only.\n\n"
        f"ZIP_SUMMARY:\n{json.dumps(payload)}"
    )


def run_ollama_analysis(config: AppConfig, payload: dict) -> dict:
    prompt = f"{SYSTEM_PROMPT}\n\n{build_analysis_prompt(payload)}"
    cmd = [
        config.ollama_command,
        "run",
        config.local_model,
        prompt,
    ]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600, check=False)
    except FileNotFoundError as ex:
        raise RuntimeError(
            "Local provider is set to ollama, but the ollama command was not found. "
            "Install Ollama and run a model first, e.g. `ollama pull llama3.1:8b`."
        ) from ex

    if proc.returncode != 0:
        raise RuntimeError(f"Ollama failed ({proc.returncode}): {proc.stderr.strip() or proc.stdout.strip()}")

    parsed = parse_json_from_text(proc.stdout)
    fixed = ensure_output_shape(parsed, payload)
    file_content = {item["path"]: item.get("content", "") for item in payload.get("files", [])}
    for issue in fixed["issues"]:
        if issue["line_number"] == 1 and issue["offending_code"] and issue["file"] in file_content:
            issue["line_number"] = guess_line_number(file_content[issue["file"]], issue["offending_code"])
    return fixed


def analyze_with_local_llm(config: AppConfig, payload: dict) -> dict:
    if config.local_provider == "ollama":
        return run_ollama_analysis(config, payload)
    raise RuntimeError(f"Unsupported local.provider: {config.local_provider}")


class ZipSecurityApp:
    def __init__(self, root: Tk):
        self.root = root
        self.root.title("Frontend ZIP Security Analyzer")
        self.root.geometry("1250x760")
        self.root.configure(bg="#0f172a")

        self.selected_files: list[Path] = []
        self.result_queue: queue.Queue = queue.Queue()
        self.results_cache = []

        self.status = StringVar(value="Upload ZIP file(s) to run local-LLM frontend security analysis.")
        self.grade = StringVar(value="--")
        self.certainty = StringVar(value="--")
        self.files_count = StringVar(value="--")
        self.issue_count = StringVar(value="--")

        self._build_ui()
        self._poll_results()

    def _build_ui(self):
        style = ttk.Style()
        style.theme_use("clam")

        style.configure("Dark.TFrame", background="#0f172a")
        style.configure("Card.TFrame", background="#111827")
        style.configure("CardTitle.TLabel", background="#111827", foreground="#9ca3af", font=("Segoe UI", 10, "bold"))
        style.configure("Metric.TLabel", background="#111827", foreground="#e5e7eb", font=("Segoe UI", 16, "bold"))
        style.configure("Header.TLabel", background="#0f172a", foreground="#e5e7eb", font=("Segoe UI", 16, "bold"))
        style.configure("Sub.TLabel", background="#0f172a", foreground="#94a3b8", font=("Segoe UI", 10))
        style.configure("Dark.TButton", background="#1f2937", foreground="#f8fafc", padding=(12, 8))

        container = ttk.Frame(self.root, style="Dark.TFrame", padding=14)
        container.pack(fill="both", expand=True)

        header = ttk.Frame(container, style="Dark.TFrame")
        header.pack(fill="x")
        ttk.Label(header, text="Frontend Security Dashboard", style="Header.TLabel").pack(anchor="w")
        ttk.Label(
            header,
            text="Local LLM analysis (SonarQube-inspired). Upload ZIPs, inspect findings, export strict JSON.",
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
        ttk.Button(controls, text="Upload ZIP Files", style="Dark.TButton", command=self.select_files).pack(side="left")
        ttk.Button(controls, text="Run Local Analysis", style="Dark.TButton", command=self.run_analysis).pack(side="left", padx=8)
        ttk.Button(controls, text="Export Visible JSON", style="Dark.TButton", command=self.save_output).pack(side="left")
        ttk.Label(controls, textvariable=self.status, style="Sub.TLabel").pack(side="left", padx=12)

        main = ttk.Panedwindow(container, orient="horizontal")
        main.pack(fill="both", expand=True)

        left = ttk.Frame(main, style="Card.TFrame", padding=10)
        right = ttk.Frame(main, style="Card.TFrame", padding=10)
        main.add(left, weight=1)
        main.add(right, weight=3)

        ttk.Label(left, text="Selected ZIP Files", style="CardTitle.TLabel").pack(anchor="w")
        self.file_list = Text(left, bg="#0b1220", fg="#d1d5db", insertbackground="#d1d5db", height=14, relief="flat")
        self.file_list.pack(fill="both", expand=True, pady=(6, 0))

        ttk.Label(right, text="Findings", style="CardTitle.TLabel").pack(anchor="w")
        cols = ("id", "severity", "file", "line", "title")
        self.issues_tree = ttk.Treeview(right, columns=cols, show="headings", height=12)
        for col, width in [("id", 90), ("severity", 90), ("file", 260), ("line", 70), ("title", 380)]:
            self.issues_tree.heading(col, text=col.upper())
            self.issues_tree.column(col, width=width, anchor="w")
        self.issues_tree.pack(fill="x", pady=(6, 8))

        ttk.Label(right, text="Strict JSON Output", style="CardTitle.TLabel").pack(anchor="w")
        self.output = Text(right, bg="#0b1220", fg="#d1d5db", insertbackground="#d1d5db", relief="flat")
        self.output.pack(fill="both", expand=True, pady=(6, 0))

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
        if not self.selected_files:
            messagebox.showwarning("No files selected", "Please upload at least one ZIP file.")
            return

        if not Path(CONFIG_FILE).exists():
            messagebox.showerror("Missing config", f"{CONFIG_FILE} was not found.")
            return

        config = load_properties(CONFIG_FILE)
        self.status.set(f"Running local analysis via {config.local_provider}:{config.local_model}...")
        self.output.delete("1.0", END)
        self._clear_findings_table()
        threading.Thread(target=self._analyze_worker, args=(config,), daemon=True).start()

    def _analyze_worker(self, config: AppConfig):
        OUTPUT_DIR.mkdir(exist_ok=True)
        aggregate = []
        try:
            for zip_path in self.selected_files:
                summary = summarize_zip(
                    zip_path,
                    config.max_files,
                    config.max_bytes_per_file,
                    config.max_total_chars,
                )
                result = analyze_with_local_llm(config, summary)
                outfile = OUTPUT_DIR / f"{zip_path.stem}.analysis.json"
                outfile.write_text(json.dumps(result, indent=2), encoding="utf-8")
                aggregate.append({"zip": str(zip_path), "output_json": str(outfile), "result": result})
            self.result_queue.put(("ok", aggregate))
        except Exception as ex:
            self.result_queue.put(("err", str(ex)))

    def _clear_findings_table(self):
        for row in self.issues_tree.get_children():
            self.issues_tree.delete(row)

    def _refresh_dashboard(self, aggregate_results: list[dict]):
        if not aggregate_results:
            return

        first = aggregate_results[0]["result"]
        all_issues = []
        for item in aggregate_results:
            all_issues.extend(item["result"].get("issues", []))

        self.grade.set(f"{first.get('overall_security_grade_percent', 0)}%")
        self.certainty.set(f"{first.get('certainty_percent', 0)}%")
        self.files_count.set(str(sum(item["result"].get("files_analyzed", 0) for item in aggregate_results)))
        self.issue_count.set(str(len(all_issues)))

        self._clear_findings_table()
        for issue in all_issues:
            self.issues_tree.insert(
                "",
                END,
                values=(
                    issue.get("id", ""),
                    issue.get("severity", ""),
                    issue.get("file", ""),
                    issue.get("line_number", ""),
                    issue.get("title", ""),
                ),
            )

    def _poll_results(self):
        try:
            status, payload = self.result_queue.get_nowait()
            if status == "ok":
                self.results_cache = payload
                self.status.set("Analysis complete.")
                self._refresh_dashboard(payload)
                self.output.insert(END, json.dumps(payload, indent=2))
            else:
                self.status.set("Analysis failed.")
                self.output.insert(END, payload)
                messagebox.showerror("Analysis failed", payload)
        except queue.Empty:
            pass
        self.root.after(250, self._poll_results)

    def save_output(self):
        content = self.output.get("1.0", END).strip()
        if not content:
            messagebox.showinfo("No output", "No JSON output is currently visible.")
            return
        save_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")])
        if not save_path:
            return
        Path(save_path).write_text(content, encoding="utf-8")
        messagebox.showinfo("Saved", f"Saved JSON to {save_path}")


if __name__ == "__main__":
    root = Tk()
    ZipSecurityApp(root)
    root.mainloop()

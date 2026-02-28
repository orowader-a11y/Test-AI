# Frontend ZIP Security Analyzer (Local LLM)

A Windows desktop app that lets you upload frontend ZIP archives, runs static frontend security analysis with a **local LLM**, and outputs strict JSON. It can optionally cross-check findings with ChatGPT when configured.

## Local-LLM approach
This app now uses a local model runtime inspired by local-LLM workflows (MCP-oriented/dev-local architecture), with **Ollama** as the default provider and optional **ChatGPT** cross-checking.

- Local analysis runs by invoking `ollama run <model> <prompt>`.
- Optional ChatGPT analysis can be enabled for side-by-side finding comparison by setting an API key environment variable.
- Models/providers are configurable in `config.properties`.

## Required local setup
Install Ollama and pull a model (example):

```bash
ollama pull llama3.1:8b
```

## Strict output JSON format
The analyzer enforces this exact shape:

```json
{
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
```

## Security checks included
The prompt requests cross-file analysis for:
- Exposed secrets/tokens
- API endpoint leaks
- Unsafe auth flows
- XSS sinks & injection vectors
- postMessage misuse
- CSP weaknesses
- Dangerous dependencies (heuristic)
- Insecure storage patterns
- Debug leftovers
- Build misconfigurations
- Public environment variable leaks
- Open redirects
- Prototype pollution vectors
- SSRF-enabling frontend patterns
- AI-generated insecure code patterns

## Configuration
Edit `config.properties`:

```properties
local.provider=ollama
local.model=llama3.1:8b
local.ollamaCommand=ollama
# optional absolute path, useful when .exe PATH does not include Ollama
local.ollamaPath=
local.temperature=0.1

# optional ChatGPT cross-check (API key stays in environment variable)
openai.model=gpt-4o-mini
openai.apiKeyEnv=OPENAI_API_KEY
openai.baseUrl=https://api.openai.com/v1/chat/completions

analysis.maxFiles=300
analysis.maxBytesPerFile=9000
analysis.maxTotalChars=180000
learning.maxExamples=6
```

## Run in development
```bash
python app.py
```

## Build Windows .exe
Run on Windows:

```bat
build_exe.bat
```

Expected executable:
- `dist\FrontendZipSecurityAnalyzer.exe`


## Troubleshooting: "Ollama command not found"
If Ollama works in your terminal but fails from the app/.exe, the process PATH is likely different.

Set an explicit absolute path in `config.properties`:

```properties
local.ollamaPath=C:\Users\<you>\AppData\Local\Programs\Ollama\ollama.exe
```

The app now tries, in order:
1. `local.ollamaPath` (if set)
2. `local.ollamaCommand`
3. `PATH` lookup
4. common install locations

This issue is unrelated to ZIP file paths; ZIP handling happens after the Ollama executable is resolved.


## Internal library cross-check (up to 3 tools)
Each run now compares local-LLM findings against up to three internal Python-based analyzers and merges all findings into the same JSON result shape used by the UI/export.

Tool selection order:
1. `sonarqube` analyzer (preferred when SonarQube Python package or `sonar-scanner` is available)
2. dependency-focused analyzer (`dep-audit-py`)
3. frontend sink/dataflow analyzer (`frontend-sast-py`)
4. secret-pattern analyzer (`secrets-py`)

Only the first 3 available analyzers are used per run.

The app can also query ChatGPT with the same prompt/temperature used for local analysis and merge those findings into the same output JSON shape when `OPENAI_API_KEY` (or configured env var) is present.

If tool findings are missed by the model (local+ChatGPT union), those misses are automatically added to learning memory so future model prompts include those patterns.

The merge stage now de-duplicates overlapping findings (including learned-pattern repeats) and computes grade/certainty with a weighted formula that factors severity mix, analyzer breadth, and model/tool agreement.

## Continuous local learning
You can iteratively improve local results without cloud training:
- Run analysis
- Click **Teach From Current Results** to save findings into `learning_memory.json`
- Future runs inject these examples into prompt context and also match learned patterns directly in code

On the **first run only**, the app also injects a built-in bootstrap set of intentionally vulnerable frontend examples (token storage, XSS sinks, wildcard `postMessage`, hardcoded secrets, open redirects, etc.) so the local model starts with calibration examples before any user history exists. After the first successful analysis, these bootstrap examples are not reused.

This is lightweight memory-based learning (few-shot + pattern reuse), not full model weight fine-tuning.

## UI update
The UI now uses a lighter, friendlier style and includes:
- KPI cards (security grade, certainty, files, issues)
- Findings table + click-to-view issue details
- Human-readable report tab and raw JSON tab

## Windows UX note
When launched as a GUI app (`pythonw`/PyInstaller `--windowed`), analysis now starts Ollama subprocesses with `CREATE_NO_WINDOW` on Windows so an extra command prompt window does not pop up during scanning.

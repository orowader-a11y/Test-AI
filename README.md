# Frontend ZIP Security Analyzer (Local LLM)

A Windows desktop app that lets you upload frontend ZIP archives, runs static frontend security analysis with a **local LLM** (no remote API), and outputs strict JSON.

## Local-LLM approach
This app now uses a local model runtime inspired by local-LLM workflows (MCP-oriented/dev-local architecture), with **Ollama** as the default provider.

- No remote OpenAI call is made.
- Analysis runs by invoking `ollama run <model> <prompt>`.
- Model/provider are configurable in `config.properties`.

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
analysis.maxFiles=300
analysis.maxBytesPerFile=9000
analysis.maxTotalChars=180000
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

## UI update
The UI was redesigned in a SonarQube-inspired style:
- Dark dashboard theme
- KPI cards (security grade, certainty, files, issues)
- Findings table + raw JSON panel

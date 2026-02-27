# Frontend ZIP Security Analyzer

Windows desktop GUI for uploading frontend ZIP archives and running ChatGPT-powered static security analysis that returns strict JSON in the exact structure requested.

## Output JSON format
The app enforces this shape:

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

## Security checks requested in the prompt
The model is instructed to evaluate, including cross-file reasoning:
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

## Configure credentials
Edit `config.properties`:

```properties
openai.apiKey=YOUR_KEY
openai.model=gpt-4.1-mini
openai.apiBase=https://api.openai.com/v1
openai.temperature=0.1
analysis.maxFiles=300
analysis.maxBytesPerFile=9000
```

## Run in development
```bash
python app.py
```

## Build a Windows .exe
Run this on Windows:

```bat
build_exe.bat
```

Expected output executable:
- `dist\FrontendZipSecurityAnalyzer.exe`

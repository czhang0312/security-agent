# Release Validation

## 0.1.0 MVP

Validated on macOS with Python 3.11.

### Test Suite

```bash
pytest -q
```

Result:

```text
37 passed
```

### Build Artifacts

```bash
python3 -m build --no-isolation
```

Artifacts produced:

- `dist/security-agent-0.1.0.tar.gz`
- `dist/security_agent-0.1.0-py3-none-any.whl`

### Fresh Install Smoke Test

```bash
python3 -m venv /tmp/security-agent-smoke
/tmp/security-agent-smoke/bin/pip install dist/security_agent-0.1.0-py3-none-any.whl
/tmp/security-agent-smoke/bin/security-agent --help
/tmp/security-agent-smoke/bin/security-agent scan --help
/tmp/security-agent-smoke/bin/security-agent advisories update --help
```

### Runtime Smoke Test

```bash
/tmp/security-agent-smoke/bin/security-agent advisories update
OPENAI_API_KEY=... /tmp/security-agent-smoke/bin/security-agent scan ../progress_tracker --investigator openai --max-investigations 1
```

Observed:

- advisory cache updated successfully
- installed CLI scanned a Rails repo successfully
- OpenAI-backed investigation completed successfully
- terminal output and exit code behavior matched the documented workflow

### Notes

- `python3 -m build` in isolated mode was blocked by sandboxed network access to package indexes, so validation used `--no-isolation` with local tooling.
- Local environment emitted non-fatal `bdist_conda` entry-point warnings during build, but both sdist and wheel were built successfully.

# Syntinel

Adversarial AI-powered code security scanner. Runs against your own codebase,
locally, before you commit.

Syntinel is the free, open-source local half of a two-surface security
system. The other half — [Syntinel Cloud](https://github.com/apps/syntinel),
a GitHub App that reviews every pull request and gates merges — is a
separate, hosted product built on top of this package.

```bash
pip install syntinel
pip install "syntinel[semgrep]"   # optional: adds the deterministic Semgrep engine
export GROQ_API_KEY=...            # required for the LLM engine

syntinel scan ./path/to/repo
syntinel scan ./app --output report.md --format markdown
syntinel scan ./app --max-files 40 --severity high
syntinel scan ./app --no-semgrep          # LLM only
syntinel scan ./app --no-llm              # Semgrep only (no API key needed)
```

## Two engines

- **LLM engine** — adversarial security review over whole files. Reads code
  the way an attacker would: null inputs, boundary conditions, injection
  paths, unhandled exceptions, concurrency bugs. Catches logic/authorization
  bugs that pattern matchers miss.
- **Semgrep engine** — deterministic static analysis using open-source
  security rulesets (`p/security-audit`, `p/secrets`). Reproducible, never
  misses a classic hardcoded secret. **Degrades gracefully**: if Semgrep
  isn't installed, the scan continues LLM-only with a warning.

Findings from both are merged and deduped on `(file, line, class)`; when both
engines agree, the finding is marked corroborated (`source: llm+semgrep`).

## Flags

| Flag | Description | Default |
|---|---|---|
| `--output`, `-o` | Report output path | `syntinel-report.*` |
| `--format`, `-f` | `markdown` \| `json` \| `both` | `markdown` |
| `--severity`, `-s` | Minimum severity to report (`low`/`medium`/`high`/`critical`) | `low` |
| `--max-files` | Scan only the N most security-relevant files | all |
| `--no-semgrep` | Disable the Semgrep pass | off |
| `--no-llm` | Disable the LLM pass | off |
| `--no-cache` | Bypass the on-disk result cache | off |
| `--concurrency` | Concurrent LLM chunk reviews | 5 |
| `--verbose`, `-v` | Verbose logging | off |

Exit code is **1 when any CRITICAL finding is present** (0 otherwise), so the
CLI is usable as a CI gate or pre-commit hook.

## Demo

`demo/vulnerable-app/` is an intentionally-insecure fixture with one seeded
instance of each vulnerability class, plus clean files to measure false
positives. Ground truth is in its `EXPECTED_FINDINGS.md`.

```bash
syntinel scan ./demo/vulnerable-app
python scripts/benchmark.py --runs 3   # measure detection vs ground truth
```

## Development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,semgrep]"
pytest
ruff check .
```

## License

MIT

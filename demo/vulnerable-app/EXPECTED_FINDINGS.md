# Expected Findings — demo/vulnerable-app

Ground truth for `scripts/benchmark.py`. One seeded vulnerability class per
file under `app/`; `clean/` holds the fixed equivalents and must produce zero
findings (false-positive check).

| File | Class | Description |
|---|---|---|
| `app/db.py` | injection | SQL built by string concatenation |
| `app/config.py` | secrets | Hardcoded Stripe secret key |
| `app/orders.py` | logic | No bounds check on discount percentage |
| `app/files.py` | other | Path traversal via unsanitized filename |
| `app/auth.py` | other | Unsalted MD5 used as a password hash |

`clean/safe_queries.py`, `clean/safe_orders.py`, `clean/password_hashing.py`
are the corresponding fixes and are expected to produce **no** findings.

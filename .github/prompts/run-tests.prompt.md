---
description: Run the full pytest suite via uv and report a concise summary.
---

# /run-tests

Execute:
```bash
uv run pytest -q
```

If the run is green, report the count (e.g. "944 passed in 2m23s").

If it fails:
1. Show the first 3 failing test ids and their short tracebacks.
2. Do NOT attempt to fix unless the user explicitly asks.
3. Suggest running a single failing test for faster iteration:
   `uv run pytest tests/test_X.py::test_Y -q -v`.

For a focused run, accept arguments:
```
/run-tests tests/test_storage_sql_repository.py
```
→ runs only that file/path.

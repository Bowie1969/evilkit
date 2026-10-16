# Contributing

EvilKit is source-available under its commercial licence and is not accepting
code contributions by default. Bug reports and design feedback are welcome;
contact **fullchecksecurity@gmail.com** before preparing a patch.

For local development, use Python 3.11 or newer:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/python -m pytest -q
```

Tests must use local fixtures and documentation-only address ranges. Never add
real credentials, client data, private topology, raw engagement output, or a
live target to the repository. New behavior that can reach a target must have a
scope-refusal test and an evidence/audit test.


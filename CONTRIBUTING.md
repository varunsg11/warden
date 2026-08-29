# Contributing

Thanks for your interest in Warden. This is a research/educational project, and
contributions, questions, and issues are welcome.

## Development setup

```bash
python -m venv .venv
# Windows:      .venv\Scripts\activate
# macOS/Linux:  source .venv/bin/activate

pip install -e ".[dev]"     # install the package + dev tooling
pre-commit install          # optional: run linters on every commit
cp .env.example .env        # add your OPENAI_API_KEY (only needed for real-model demos)
```

## The golden rule of this codebase

**No code in `src/warden/governance/` may call an LLM.** Every authorization
decision must be made by deterministic Python. This is the security invariant the
whole project exists to enforce — a change that violates it defeats the design.

## Checks (all must pass; CI enforces them)

```bash
ruff format .          # format
ruff check .           # lint
mypy                   # type-check
pytest --cov           # tests + coverage
```

Or, with `make`:

```bash
make check             # lint + type-check + tests
```

## Conventions

- Line length 100, formatted by `ruff format`.
- Public functions and classes are type-annotated; `src/warden/py.typed` ships types.
- Tests live in `tests/`, named `test_*.py`, and must be deterministic (no network).
  Use `WARDEN_FAKE_LLM=1` / the fake backend for anything touching the pipeline.
- Keep the governance core free of third-party surprises: prefer the standard library.

## Pull requests

1. Branch from `main`.
2. Make the change with a test that covers it.
3. Ensure `make check` is green.
4. Open a PR describing the change and the security reasoning where relevant.

# Contributing to pki-core

Thank you for your interest in contributing to pki-core. This project is maintained by MeV Technology Consulting, LLC and we welcome contributions from the community.

## Getting Started

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone git@github.com:YOUR-USERNAME/pki-core.git
   cd pki-core
   ```
3. Create a virtual environment and install dev dependencies:
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   pip install -e ".[dev]"
   ```
4. Install pre-commit hooks:
   ```bash
   pre-commit install
   ```

## Development

### Running Tests

```bash
pytest
```

### Linting and Formatting

This project uses [ruff](https://docs.astral.sh/ruff/) for linting and formatting, and [mypy](https://mypy-lang.org/) for type checking.

```bash
ruff check .
ruff format .
mypy src/pki/core/
```

Pre-commit hooks will run these automatically on each commit.

### Security Scanning

```bash
bandit -r src/pki/core/
pip-audit
```

Bandit is configured in `pyproject.toml` with the following suppressions:

- **`exclude_dirs = ["tests"]`** — Test code uses self-signed certificates and intentionally
  exercises error paths. Scanning test fixtures produces false positives.
- **`B101`** (`assert`) — `assert` is used in tests and for internal invariants that are
  not security-relevant. Runtime input validation uses explicit exceptions, not `assert`.
- **`B110`** (`try/except/pass`) — Used in best-effort cleanup paths (e.g., CRL cache fallback)
  where silently continuing is the intended behavior.

## Submitting Changes

1. Create a feature branch from `main`:
   ```bash
   git checkout -b your-feature-name
   ```
2. Make your changes and add tests for any new functionality
3. Ensure all tests pass and linting is clean
4. Commit with a clear message describing the change
5. Push to your fork and open a pull request against `main`

## Pull Request Guidelines

- Keep PRs focused — one feature or fix per PR
- Include tests for new functionality
- Update the CHANGELOG.md under an `## [Unreleased]` section
- Ensure CI passes before requesting review

## Reporting Issues

- **Bugs and feature requests**: Open a GitHub issue
- **Security vulnerabilities**: Email info.security@mevtc.com (do not open a public issue)

## Code Style

- Follow the existing code patterns in the project
- ruff and mypy configuration in `pyproject.toml` defines the project standards
- Target Python 3.11+

## License

By contributing, you agree that your contributions will be licensed under the BSD 3-Clause License.

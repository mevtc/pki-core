# Publishing to GitHub

This project is maintained on an internal GitLab instance (`repo.mevtc.com`) and
selectively published to GitHub (`github.com/mevtc/pki-core`).

The `github-release` branch is the public-facing branch. It is pushed to GitHub
as `main`. Not all commits from the internal `main` branch need to be published.

## Remotes

```
origin  → repo.mevtc.com/mevtc/pki-core   (internal)
github  → github.com/mevtc/pki-core        (public)
```

If the `github` remote is not configured:

```bash
git remote add github git@github.com:mevtc/pki-core.git
```

## Publishing Changes

1. Switch to the release branch:
   ```bash
   git checkout github-release
   ```

2. Bring in changes from `main` — either all of them or specific commits:
   ```bash
   # Everything since last sync:
   git merge main

   # Or specific commits only:
   git cherry-pick <commit-hash>
   ```

3. Verify CI passes locally:
   ```bash
   ruff check . && ruff format --check .
   mypy pki_core
   pytest --tb=short
   ```

4. Push to GitHub:
   ```bash
   git push github github-release:main
   ```

5. Push the updated branch back to GitLab:
   ```bash
   git push origin github-release
   ```

6. Return to main:
   ```bash
   git checkout main
   ```

## Handling GitHub Contributions

When an external contributor opens a PR on GitHub:

1. Review and merge the PR on GitHub (this updates `github-release` on GitHub)
2. Pull the changes locally:
   ```bash
   git fetch github
   git checkout github-release
   git pull github main
   ```
3. Cherry-pick into internal `main`:
   ```bash
   git checkout main
   git cherry-pick <commit-hash>
   git push origin main
   ```
4. Push the updated `github-release` to GitLab:
   ```bash
   git push origin github-release
   ```

## Files That Differ Between Branches

| File               | `main` (internal) | `github-release` (public) |
| ------------------ | ------------------ | ------------------------- |
| `.gitlab-ci.yml`   | Present            | Absent                    |
| `.github/workflows/ci.yml` | Present   | Present                   |
| `PUBLISHING.md`    | Present            | Absent                    |

## Publishing to PyPI

```bash
pip install build twine
python -m build
twine upload dist/*
```

Use an API token from https://pypi.org/manage/account/token/.
Username: `__token__`, password: the token value.

Test on TestPyPI first:
```bash
twine upload --repository testpypi dist/*
```

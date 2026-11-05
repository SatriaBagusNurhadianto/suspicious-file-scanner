# Contributing

## Workflow

1. Fork and create a branch: `feat/<name>`, `fix/<name>`, `docs/<name>`, `chore/<name>`.
2. Keep changes small and focused. One PR = one problem.
3. Run lint and tests before committing:
   ```bash
   ruff check src tests
   pytest
   ```
4. Use Conventional Commits: `feat:`, `fix:`, `docs:`, `refactor:`, `chore:`, `ci:`, `test:`.
5. Open a PR using the template.

## Safety

- Never commit malware samples or scan reports.
- Test with EICAR first. Real samples only in an isolated VM.
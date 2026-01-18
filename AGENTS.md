# Repository Guidelines

This repository is currently empty (no source files or Git history). The guidance below establishes a baseline for contributors until project-specific conventions are added. Update this document as the codebase and tooling land.

## Project Structure & Module Organization

- Source code: create a top-level `src/` directory for primary modules.
- Tests: place automated tests in `tests/` or a language-standard location (e.g., `src/__tests__/`).
- Supporting files: keep scripts in `scripts/`, docs in `docs/`, and assets in `assets/` when applicable.
- Keep the repository root minimal: configs and entry points only (e.g., `README.md`, `Makefile`).

## Build, Test, and Development Commands

No build system is configured yet. When adding one, document the exact commands here and ensure they are runnable from the repo root.

Examples to replace with real commands:
- `make build` — build binaries or bundles.
- `make test` — run the test suite.
- `./scripts/dev.sh` — start a local dev loop.

## Coding Style & Naming Conventions

- Formatting: prefer language-native formatters (e.g., `gofmt`, `black`, `prettier`) and run them in CI once configured.
- Indentation: follow the language’s standard (spaces vs tabs) and avoid mixed styles.
- Naming: use `PascalCase` for types/classes, `camelCase` for functions/vars, and `snake_case` only where the language prefers it.

## Testing Guidelines

- Add tests with every feature or bug fix; avoid untested changes unless trivial.
- Name tests using the framework’s conventions (e.g., `*_test.go`, `test_*.py`, `*.spec.ts`).
- Document coverage expectations once a test runner is chosen.

## Commit & Pull Request Guidelines

- No commit history exists yet; default to Conventional Commits (e.g., `feat:`, `fix:`, `docs:`) until the project defines its own style.
- PRs should include: a short summary, testing notes (commands and results), and screenshots for UI changes.
- Link related issues when applicable and call out any follow-up work.

## Security & Configuration

- Do not commit secrets. Use `.env` or a local config file and document required keys in `README.md`.
- If introducing configuration files, add examples (e.g., `.env.example`) and keep defaults safe.

# Website Passive Reconnaissance (WPR) - Claude Code Instructions

## Project Overview

Automated passive reconnaissance tool for website assessments.

- **Language:** Python >= 3.12.
- **Dependency Management:** `uv`.

## Development Workflow

### Commands

- **Install Dependencies:** `uv sync`.
- **Linting:** `ruff check .`
- **Formatting:** `ruff format .` or `isort . && autopep8 --in-place --recursive .`
- **Run Tool:** `uv run wpr`

### Coding Standards

- **Source Layout:** All code resides in `src/wpr/`.
- **Formatting:** Adhere to `ruff` configuration (line-length: 320).
- **Type Hints:** Use `PEP 484` type hints for all new functions and methods.
- **Output:** Use the `rich` library for all terminal output to maintain consistent styling.
- **Documentation:** Maintain existing Markdown documentation style and update `README.md` for new features.
- **Data Description:** All `OSINTProviderData` subclasses must define a `description_of_data_type` class attribute.

## Security Guidelines

### General

- Never execute a system command using information retrieved from a data provider.

### Secrets

- Never hardcode API keys.
- Always use the INI configuration file pattern described in `README.md`.
- Never commit the INI configuration file into git.
- Never add the INI configuration file to git.

### Dependencies

- Only add dependencies that are actively maintained, have more than one maintainer, and have no known critical CVEs.
- Always run `pip-audit` when an new dependency is added and fail if any medium/high CVE is found.

### Network communication

- Always set explicit timeouts on all network calls (HTTP, DNS, socket).
- Never use blocking calls without a timeout.

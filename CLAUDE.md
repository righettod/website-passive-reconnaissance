# Website Passive Reconnaissance (WPR) - Claude Code Instructions

## Project Overview

Automated passive reconnaissance tool for website assessments.

- **Language:** Python >= 3.13.
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
- **Type Hints:** Use PEP 484 type hints for all new functions and methods.
- **Output:** Use the `rich` library for all terminal output to maintain consistent styling.
- **Documentation:** Maintain existing Markdown documentation style and update `README.md` for new features.
- **Data Description:** OSINTProviderData objects should include a `description_of_data_type` attribute to describe the nature of the data returned.

## Safety & Security

- **API Keys:** Never hardcode API keys. Always use the INI configuration file pattern described in `README.md`.
- **Sensitive Data:** Ensure any debug logging excludes sensitive reconnaissance results or API credentials.
- **Third Party Package:** Ensure that any proposed package is actively maintained and be maintained by more than one person.

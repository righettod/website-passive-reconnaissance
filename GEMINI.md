# Website Passive Reconnaissance (WPR) - Gemini Instructions

## Project Overview

Automated passive reconnaissance tool for website assessments.

- **Language:** Python >= 3.13
- **Dependency Management:** `uv` (preferred) or `pip`
- **Core Libraries:** `beautifulsoup4`, `httpx`, `rich`, `dnspython`, `tldextract`, `requests`

## Development Workflow

### Commands

- **Install Dependencies:** `uv sync` or `pip install -e .`
- **Linting:** `ruff check .`
- **Formatting:** `ruff format .` or `isort . && autopep8 --in-place --recursive .`
- **Run Tool:** `uv run wpr`

### Coding Standards

- **Source Layout:** All code resides in `src/wpr/`.
- **Formatting:** Adhere to `ruff` configuration (line-length: 320).
- **Type Hints:** Use PEP 484 type hints for all new functions and methods.
- **Output:** Use the `rich` library for all terminal output to maintain consistent styling.
- **Documentation:** Maintain existing Markdown documentation style and update `README.md` for new features.
- **API Key Usage:** Provider classes should implement a `use_api_key()` method. If an API key is required, this method should return `True` and the API key should be passed to the provider's constructor. If no API key is used, it should return `False`.
- **Data Description:** OSINTProviderData objects should include a `description_of_data_type` attribute to describe the nature of the data returned.

## Safety & Security

- **API Keys:** Never hardcode API keys. Always use the INI configuration file pattern described in `README.md`.
- **Sensitive Data:** Ensure any debug logging excludes sensitive reconnaissance results or API credentials.

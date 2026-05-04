# AI Analysis Worker & macOS Compatibility Fixes

This document summarizes the changes made to integrate the AI Analysis worker and improve macOS compatibility for the Pandora project.

## 🧠 AI Analysis Worker

A new worker has been added to perform static analysis on files for exposed secrets, PII, and risky configurations.

### Key Features
- **Secret Detection**: Detects over 40 types of secrets including OpenAI keys, AWS keys, GitHub tokens, Bearer tokens, and hardcoded passwords.
- **PII Detection**: Identifies Personal Identifiable Information such as SSNs, Passport numbers, Credit Card numbers, IBANs, and health-related data.
- **Risk Scoring**: Assigns a weighted risk score (0.0 to 1.0) and a risk level (`none`, `low`, `medium`, `high`) based on the severity of findings.
- **Masking**: Automatically masks sensitive values in the reports to prevent further exposure in the UI.

### Location
- **Logic**: `pandora/workers/ai_analysis/ai_analysis.py`
- **Config**: `pandora/workers/ai_analysis.yml.sample`
- **Tests**: `tests/test_ai_analysis.py`

---

## 🍎 macOS Compatibility Improvements

Several changes were made to ensure Pandora can be developed and run on macOS systems.

### Multiprocessing Fix
- **File**: `bin/workers_manager.py`
- **Change**: Forced the `fork` start method on macOS to resolve `TypeError: cannot pickle '_thread.lock'`. This allows the workers manager to successfully spawn worker processes on Darwin-based systems.

### Dependency Gracefulness
- **File**: `bin/unoserver_launcher.py`
- **Change**: Added graceful error handling for missing `uno` (LibreOffice) libraries. The system will now log a warning and disable the service instead of crashing the entire application boot process.

---

## 🧪 Verification

### Running Unit Tests
You can verify the AI worker logic independently:
```bash
python3 -m unittest discover -s tests -p 'test_ai_analysis.py'
```

### Running the Full System
To test locally on macOS (assuming Redis is installed via Homebrew):
1. Set the environment: `export PANDORA_HOME=$(pwd)`
2. Initialize config: `cp config/generic.json.sample config/generic.json`
3. Run: `poetry run start`

---

## 📝 PR Notes for Maintainers
If submitting this as a Pull Request:
1. **Include** the `pandora/workers/ai_analysis/` directory.
2. **Include** the `tests/test_ai_analysis.py` file.
3. **Include** the compatibility fixes in `bin/workers_manager.py` and `bin/unoserver_launcher.py`.
4. **Exclude** any local configuration files (`config/*.json`) or local database script workarounds.

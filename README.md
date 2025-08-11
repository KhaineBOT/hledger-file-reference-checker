# hledger Journal File Validation Tool

A comprehensive validator for [hledger](https://hledger.org) journal files.  
It ensures **bidirectional integrity** between journal file references and the actual filesystem, validates `include` directives, checks filename formats, and optionally integrates as a Git pre-commit hook.

---

## Features

- **Recursive include parsing**  
  Traverses all `include` statements to build a complete set of processed journal files.

- **File reference validation**  
  Extracts file references from specific comment patterns and checks that they exist.

- **Orphan detection**  
  Identifies files present in referenced directories but not mentioned in any journal.

- **Include coverage check**  
  Ensures every `*.journal` file is explicitly included somewhere in the journal hierarchy.

- **Filename date validation**  
  Validates that referenced files follow the `YYYYMMDD - description` format and, optionally, fall within the journal’s financial year.

- **Whitelist support**  
  Allows certain filenames to be exempt from date validation.

- **Git integration**  
  Runs automatically before commits as a Git pre-commit hook.

- **Read-only operation**  
  Never modifies journal files or filesystem contents.

---

## Installation

(Optional) Install as a Git pre-commit hook for automated validation:
`./hledger_validator.py --install-git-hook /path/to/main.journal`

## Usage
Basic validation:
`./hledger_validator.py /path/to/main.journal`

### Verbose output:
`./hledger_validator.py -v /path/to/main.journal`

### Skip orphaned file checks:
`./hledger_validator.py --skip-orphan-check /path/to/main.journal`

### Skip filename format checks:
`./hledger_validator.py --skip-filename-check /path/to/main.journal`

### Generate a report only:
`./hledger_validator.py --report-only /path/to/main.journal > report.txt`

### Run in Git pre-commit mode (manual invocation):
`./hledger_validator.py --git-hook /path/to/main.journal`

## Whitelist File
To exempt specific filenames from date validation, create a .hledger-validation-whitelist file in the same directory as your main journal or specify it explicitly.

Example .hledger-validation-whitelist:

# Ignore these files for date format check

```
legacy-document.pdf
20200100 - placeholder.txt
```


## Report Example
After running, the tool generates a detailed report:

```
================================================================================
HLEDGER JOURNAL VALIDATION REPORT
================================================================================

SUMMARY
----------------------------------------
Processed journals: 5
Total file references: 42
Referenced directories: 3
Missing referenced files: 1
Orphaned files: 2
Filesystem journal files: 5
Unincluded journal files: 1

MISSING REFERENCED FILES
----------------------------------------
❌ /path/to/missing-file.pdf
   Referenced in: /path/to/journal.journal:42

UNINCLUDED JOURNAL FILES
----------------------------------------
📋 /path/to/unincluded.journal
   Suggested include: include subdir/unincluded.journal

INVALID FILENAMES
----------------------------------------
❌ /path/to/file.txt
   Reason: Invalid filename format (expected 'YYYYMMDD - ')
   Referenced in: /path/to/journal.journal:10

================================================================================
VALIDATION COMPLETE
================================================================================
```

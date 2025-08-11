#!/usr/bin/env python3
"""
hledger Journal File Validation Tool

A comprehensive validator for hledger journal files that ensures bidirectional
integrity between file references in journal comments and the actual filesystem,
plus validation of journal file includes and git hook integration.

Features:
- Recursively processes all included journal files
- Extracts file references from specific comment patterns
- Validates referenced files exist on filesystem
- Identifies orphaned files in referenced directories
- Validates that all *.journal files are properly included
- Git pre-commit hook integration for automated validation
- Generates comprehensive validation reports
- Operates in completely read-only mode
"""

import os
import re
import sys
import subprocess
from pathlib import Path
from collections import defaultdict
from typing import Set, List, Dict, Tuple, Optional
from datetime import date
import argparse


class HledgerValidator:
    """
    Main validator class for hledger journal files and their file references.
    """

    def __init__(self, main_journal_path: str, verbose: bool = False, skip_orphan_check: bool = False,
                 git_mode: bool = False, whitelist_file: Optional[str] = None):
        """
        Initialize the validator.

        Args:
            main_journal_path: Path to the main hledger journal file
            verbose: Enable verbose output
            skip_orphan_check: Skip checking for orphaned files (only validate references)
            skip_filename_check: Skip filename format check (YYYMMDD)
            git_mode: Enable git pre-commit hook mode
        """
        self.main_journal_path = Path(main_journal_path).resolve()
        self.verbose = verbose
        self.skip_orphan_check = skip_orphan_check
        self.skip_filename_check = skip_orphan_check
        self.git_mode = git_mode

        # Default whitelist filename
        self.default_whitelist_filename = '.hledger-validation-whitelist'

        # Track processed journals to avoid infinite loops
        self.processed_journals: Set[Path] = set()

        # Store all file references with their source journal
        self.file_references: Dict[Path, List[Tuple[Path, int]]] = defaultdict(list)

        # Track all directories that contain referenced files
        self.referenced_directories: Set[Path] = set()

        # Track all journal files found in the filesystem
        self.filesystem_journals: Set[Path] = set()

        # Validation results
        self.missing_files: List[Tuple[Path, Path, int]] = []
        self.orphaned_files: List[Path] = []
        self.unincluded_journals: List[Path] = []
        self.invalid_date_files: List[Tuple[Path, Path, int, str]] = []  # Added for date validation issues

        # Whitelist for date validation exemptions
        self.date_validation_whitelist: Set[str] = set()
        self.whitelist_path: Optional[Path] = None

        # Load whitelist (either specified or default)
        if whitelist_file:
            self._load_whitelist(whitelist_file)
        else:
            # Try to load default whitelist from main journal directory
            default_whitelist = self.main_journal_path.parent / self.default_whitelist_filename
            if default_whitelist.exists():
                self._load_whitelist(str(default_whitelist))

        # Compile regex patterns for performance
        self.include_pattern = re.compile(r'^\s*include\s+(.+)$', re.IGNORECASE)
        self.file_ref_patterns = [
            re.compile(r'^\s*;\s*(\.\/[^\s].*)$'),  # "; ./folder/file"
            re.compile(r'^\s*;\s*Receipt\s+(\.\/[^\s].*)$', re.IGNORECASE)  # "; Receipt ./folder/file"
        ]

        # Date validation patterns
        self.filename_date_pattern = re.compile(r'^(\d{8})\s*-\s*.*$')
        self.journal_fy_pattern = re.compile(r'^(\d{4})-(\d{2})\.journal$')

    def _load_whitelist(self, whitelist_file: str) -> None:
        """
        Load filenames from whitelist file that should be exempt from date validation.

        Args:
            whitelist_file: Path to the whitelist file
        """
        whitelist_path = Path(whitelist_file)

        try:
            if not whitelist_path.exists():
                self.log(f"Whitelist file not found: {whitelist_path} - proceeding without whitelist", "WARNING")
                return

            if not whitelist_path.is_file():
                self.log(f"Whitelist path is not a file: {whitelist_path} - proceeding without whitelist", "WARNING")
                return

            with open(whitelist_path, 'r', encoding='utf-8') as file:
                for line_num, line in enumerate(file, 1):
                    # Strip whitespace and skip empty lines and comments
                    cleaned_line = line.strip()
                    if not cleaned_line or cleaned_line.startswith('#'):
                        continue

                    # Add filename to whitelist
                    self.date_validation_whitelist.add(cleaned_line)
                    self.log(f"Added to date validation whitelist: {cleaned_line}")

            self.log(f"Loaded {len(self.date_validation_whitelist)} entries from whitelist file: {whitelist_path}")

        except Exception as e:
            self.log(f"Error reading whitelist file {whitelist_path}: {e} - proceeding without whitelist", "WARNING")

    def _is_whitelisted(self, filename: str) -> bool:
        """
        Check if a filename is whitelisted for date validation exemption.

        Args:
            filename: The filename to check

        Returns:
            True if the filename is whitelisted, False otherwise
        """
        return filename in self.date_validation_whitelist

        # Compile regex patterns for performance
        self.include_pattern = re.compile(r'^\s*include\s+(.+)$', re.IGNORECASE)
        self.file_ref_patterns = [
            re.compile(r'^\s*;\s*(\.\/[^\s].*)$'),  # "; ./folder/file"
            re.compile(r'^\s*;\s*Receipt\s+(\.\/[^\s].*)$', re.IGNORECASE)  # "; Receipt ./folder/file"
        ]

    def log(self, message: str, level: str = "INFO") -> None:
        """Log messages with optional verbosity control."""
        if self.git_mode:
            # In git mode, only show errors and warnings
            if level in ["ERROR", "WARNING"]:
                print(f"[{level}] {message}")
        elif self.verbose or level in ["ERROR", "WARNING"]:
            print(f"[{level}] {message}")

    def get_git_tracked_files(self) -> Set[Path]:
        """
        Get all .journal files tracked by git in the repository.

        Returns:
            Set of paths to .journal files tracked by git
        """
        git_journals = set()

        try:
            # Get git repository root
            result = subprocess.run(
                ['git', 'rev-parse', '--show-toplevel'],
                capture_output=True,
                text=True,
                check=True
            )
            git_root = Path(result.stdout.strip())

            # Get all tracked files
            result = subprocess.run(
                ['git', 'ls-files', '*.journal'],
                capture_output=True,
                text=True,
                check=True,
                cwd=git_root
            )

            for file_line in result.stdout.strip().split('\n'):
                if file_line.strip():
                    journal_path = (git_root / file_line.strip()).resolve()
                    git_journals.add(journal_path)
                    self.log(f"Found git-tracked journal: {journal_path}")

        except subprocess.CalledProcessError as e:
            self.log(f"Error getting git-tracked files: {e}", "WARNING")
        except FileNotFoundError:
            self.log("Git not found - scanning filesystem instead", "WARNING")

        return git_journals

    def find_journal_files(self, search_root: Optional[Path] = None) -> Set[Path]:
        """
        Find all .journal files in the filesystem or git repository.

        Args:
            search_root: Root directory to search (defaults to main journal's directory)

        Returns:
            Set of paths to .journal files found
        """
        if self.git_mode:
            # In git mode, only consider git-tracked files
            return self.get_git_tracked_files()

        # Filesystem mode - search from the main journal's directory
        if search_root is None:
            search_root = self.main_journal_path.parent

        journal_files = set()

        try:
            # Search for all .journal files recursively
            for journal_path in search_root.rglob('*.journal'):
                if journal_path.is_file():
                    # Skip hidden files and files in hidden directories
                    if not self._is_hidden_path(journal_path):
                        journal_files.add(journal_path.resolve())
                        self.log(f"Found journal file: {journal_path}")

        except Exception as e:
            self.log(f"Error scanning for journal files: {e}", "ERROR")

        return journal_files

    def parse_journal_file(self, journal_path: Path, parent_dir: Optional[Path] = None) -> None:
        """
        Parse a journal file and recursively process includes and file references.

        Args:
            journal_path: Path to the journal file to parse
            parent_dir: Parent directory for resolving relative paths
        """
        # Resolve the absolute path
        if parent_dir and not journal_path.is_absolute():
            resolved_path = (parent_dir / journal_path).resolve()
        else:
            resolved_path = journal_path.resolve()

        # Avoid processing the same journal twice
        if resolved_path in self.processed_journals:
            self.log(f"Skipping already processed journal: {resolved_path}")
            return

        # Check if journal file exists
        if not resolved_path.exists():
            self.log(f"Journal file not found: {resolved_path}", "ERROR")
            return

        if not resolved_path.is_file():
            self.log(f"Path is not a file: {resolved_path}", "ERROR")
            return

        self.processed_journals.add(resolved_path)
        self.log(f"Processing journal: {resolved_path}")

        # Get the directory containing this journal for resolving relative paths
        journal_dir = resolved_path.parent

        try:
            with open(resolved_path, 'r', encoding='utf-8') as file:
                for line_num, line in enumerate(file, 1):
                    line = line.strip()

                    # Skip empty lines
                    if not line:
                        continue

                    # Check for include directives
                    include_match = self.include_pattern.match(line)
                    if include_match:
                        include_path = include_match.group(1).strip()
                        # Remove quotes if present
                        include_path = include_path.strip('\'"')
                        self.log(f"Found include directive: {include_path} (line {line_num})")

                        # Recursively process included journal
                        self.parse_journal_file(Path(include_path), journal_dir)
                        continue

                    # Check for file references in comments
                    for pattern in self.file_ref_patterns:
                        match = pattern.match(line)
                        if match:
                            # inside parse_journal_file(), where you handle file references:
                            file_path = match.group(1).strip()
                            # Remove quotes if present
                            file_path = file_path.strip('\'"')

                            self.log(f"Found file reference: {file_path} (line {line_num})")

                            # If the comment provides only a directory (trailing slash or '.' style), skip it.
                            # Examples to skip: "./receipts/", "receipts/", "./", ".", "../"
                            if file_path.endswith(('/', '\\')) or file_path in ('.', './', '..', '../'):
                                self.log(f"Skipping directory-only reference: {file_path} (in {resolved_path}:{line_num})", "INFO")
                                break  # or `continue` to next line (use `break` only if inside loop that checks patterns; original code used break after match)

                            # Remove leading ./ if present (existing logic)
                            if file_path.startswith('./'):
                                file_path = file_path[2:]  # Remove './'

                            # If after normalization the path is empty, skip
                            if not file_path.strip():
                                self.log(f"Skipping empty/invalid file reference (after normalization): {match.group(1)} "
                                         f"(in {resolved_path}:{line_num})", "INFO")
                                break

                            # Resolve relative path from journal's directory and store
                            referenced_file = (journal_dir / file_path).resolve()
                            self.file_references[referenced_file].append((resolved_path, line_num))
        except Exception as e:
            self.log(f"Error reading journal file {resolved_path}: {e}", "ERROR")

    def validate_file_references(self) -> None:
        """
        Validate that all referenced files exist on the filesystem.
        """
        self.log("Validating file references...")

        for file_path, references in self.file_references.items():
            if not file_path.exists():
                for journal_path, line_num in references:
                    self.missing_files.append((file_path, journal_path, line_num))
                    self.log(f"Missing file: {file_path} (referenced in {journal_path}:{line_num})", "WARNING")

    def validate_journal_includes(self) -> None:
        """
        Validate that all .journal files are properly included.
        """
        self.log("Validating journal includes...")

        # Find all journal files in the filesystem/git
        self.filesystem_journals = self.find_journal_files()

        # The main journal file should not be considered as needing inclusion
        main_journal_resolved = self.main_journal_path.resolve()

        # Debug output
        if self.verbose:
            self.log(f"Found {len(self.filesystem_journals)} journal files in filesystem")
            self.log(f"Processed {len(self.processed_journals)} journal files")
            self.log("Filesystem journals:")
            for j in sorted(self.filesystem_journals):
                self.log(f"  - {j}")
            self.log("Processed journals:")
            for j in sorted(self.processed_journals):
                self.log(f"  - {j}")

        # Find journals that exist but are not included
        for journal_file in self.filesystem_journals:
            # Skip the main journal file itself
            if journal_file == main_journal_resolved:
                self.log(f"Skipping main journal: {journal_file}")
                continue

            # Skip if this journal is actually processed (which means it was included and parsed)
            if journal_file in self.processed_journals:
                self.log(f"Journal properly included: {journal_file}")
                continue

            # This journal exists but was not processed, so it's not included
            self.unincluded_journals.append(journal_file)
            self.log(f"Unincluded journal found: {journal_file}", "WARNING")

    def find_orphaned_files(self) -> None:
        """
        Find files in referenced directories that aren't mentioned in any journal.
        Note: This excludes .journal files, which are handled by validate_journal_includes().
        """
        if self.skip_orphan_check:
            self.log("Skipping orphaned files check (disabled)")
            return

        self.log("Scanning for orphaned files...")

        # Get all referenced files
        referenced_files = set(self.file_references.keys())

        # Scan each directory that contains referenced files
        for directory in self.referenced_directories:
            if not directory.exists():
                self.log(f"Referenced directory does not exist: {directory}", "WARNING")
                continue

            try:
                # Recursively scan directory for all files
                for file_path in directory.rglob('*'):
                    if file_path.is_file():
                        # Skip hidden files and files in hidden directories
                        if self._is_hidden_path(file_path):
                            continue

                        # Skip .journal files - these are handled by validate_journal_includes()
                        if file_path.suffix.lower() == '.journal' or file_path.suffix.lower() == '.prices':
                            continue

                        # Check if this file is referenced
                        if file_path.resolve() not in referenced_files:
                            self.orphaned_files.append(file_path.resolve())
                            self.log(f"Orphaned file found: {file_path}", "WARNING")

            except Exception as e:
                self.log(f"Error scanning directory {directory}: {e}", "ERROR")

    def validate_filenames(self) -> None:
      """
      Validate that referenced filenames follow the 'YYYYMMDD - ' format and (optionally)
      that they fall within the financial year of the journal.

      - Always checks filename date prefix matches ^YYYYMMDD -
      - If journal filename matches YYYY-YY.journal, check that file dates fall within
        that financial year (1 July -> 30 June).
      - Skip FY check if journal is not named correctly or filename is whitelisted.
      - Skip checking for files with .journal or .prices extensions.
      - Ignore directory-only references (either existing dirs or ones skipped at parse time).
      """
      from datetime import date

      self.log("Validating filenames...")

      # Determine financial year bounds from main journal name if possible
      fy_match = self.journal_fy_pattern.match(self.main_journal_path.name)
      if fy_match:
          start_year = int(fy_match.group(1))
          # compute full end year (e.g. "2020-21" -> 2021)
          end_year = int(fy_match.group(2)) + (start_year // 100) * 100
          fy_start_date = date(start_year, 7, 1)
          fy_end_date = date(end_year, 6, 30)
          fy_check_enabled = True
      else:
          fy_check_enabled = False

      for file_path, references in self.file_references.items():
          # file_path is a Path (absolute/resolved)
          filename = file_path.name.strip()

          # If name is empty (defensive) skip
          if not filename:
              # likely a weird reference — skip rather than error
              continue

          # If the referenced path exists and is a directory, skip filename checks
          try:
              if file_path.exists() and file_path.is_dir():
                  # directory refs shouldn't be validated for filename format
                  continue
          except Exception:
              # If filesystem check errors, continue defensively to avoid crashing validation
              pass

          # Skip entries explicitly whitelisted
          if self._is_whitelisted(filename):
              continue

          # Skip .journal and .prices files entirely
          suffix = file_path.suffix.lower()
          if suffix in ('.journal', '.prices'):
              continue

          # Validate filename starts with YYYYMMDD -
          date_match = self.filename_date_pattern.match(filename)
          if not date_match:
              for journal_path, line_num in references:
                  self.invalid_date_files.append(
                      (file_path, journal_path, line_num, "Invalid filename format (expected 'YYYYMMDD - ')")
                  )
                  self.log(f"Invalid filename format: {filename} (in {journal_path}:{line_num})", "WARNING")
              continue

          date_str = date_match.group(1)
          try:
              file_date = date(
                  int(date_str[0:4]),
                  int(date_str[4:6]),
                  int(date_str[6:8])
              )
          except ValueError as e:
              # Catches impossible dates (e.g., 20240230)
              for journal_path, line_num in references:
                  self.invalid_date_files.append(
                      (file_path, journal_path, line_num, f"Invalid calendar date in filename: {e}")
                  )
                  self.log(f"Invalid calendar date in filename: {filename} ({e}) "
                           f"(in {journal_path}:{line_num})", "WARNING")
              continue

          # Optional financial year check
          if fy_check_enabled:
              if not (fy_start_date <= file_date <= fy_end_date):
                  for journal_path, line_num in references:
                      self.invalid_date_files.append(
                          (file_path, journal_path, line_num,
                           f"Date not in FY {start_year}-{str(end_year)[-2:]}")
                      )
                      self.log(
                          f"Date {file_date} not in financial year {start_year}-{str(end_year)[-2:]} "
                          f"(in {journal_path}:{line_num})",
                          "WARNING"
                      )

    def _is_hidden_path(self, file_path: Path) -> bool:
        """"
        Check if a file path contains any hidden components (starting with '.').

        Args:
            file_path: Path to check

        Returns:
            True if the path or any of its parent directories start with '.'
        """
        # Check if the file itself starts with '.'
        if file_path.name.startswith('.'):
            return True

        # Check if any parent directory in the path starts with '.'
        for part in file_path.parts:
            if part.startswith('.') and part not in ['.', '..']:
                return True

        return False

    def generate_report(self) -> str:
        """
        Generate a comprehensive validation report.

        Returns:
            Formatted report string
        """
        report = []
        report.append("=" * 80)
        report.append("HLEDGER JOURNAL VALIDATION REPORT")
        report.append("=" * 80)
        report.append("")

        # Summary
        report.append("SUMMARY")
        report.append("-" * 40)
        report.append(f"Processed journals: {len(self.processed_journals)}")
        report.append(f"Total file references: {len(self.file_references)}")
        report.append(f"Referenced directories: {len(self.referenced_directories)}")
        report.append(f"Missing referenced files: {len(self.missing_files)}")
        report.append(f"Orphaned files: {len(self.orphaned_files)}")
        report.append(f"Filesystem journal files: {len(self.filesystem_journals)}")
        report.append(f"Unincluded journal files: {len(self.unincluded_journals)}")
        report.append("")

        # Processed journals
        if self.processed_journals:
            report.append("PROCESSED JOURNALS")
            report.append("-" * 40)
            for journal in sorted(self.processed_journals):
                report.append(f"  {journal}")
            report.append("")

        # Missing files
        if self.missing_files:
            report.append("MISSING REFERENCED FILES")
            report.append("-" * 40)
            for missing_file, journal_path, line_num in sorted(self.missing_files):
                report.append(f"  ❌ {missing_file}")
                report.append(f"     Referenced in: {journal_path}:{line_num}")
                report.append("")
        else:
            report.append("✅ All referenced files exist on filesystem")
            report.append("")

        # Unincluded journals
        if self.unincluded_journals:
            report.append("UNINCLUDED JOURNAL FILES")
            report.append("-" * 40)
            report.append("The following .journal files exist but are not included:")
            report.append("")
            for unincluded_journal in sorted(self.unincluded_journals):
                report.append(f"  📋 {unincluded_journal}")
                # Suggest include directive
                try:
                    rel_path = unincluded_journal.relative_to(self.main_journal_path.parent)
                    report.append(f"     Suggested include: include {rel_path}")
                except ValueError:
                    report.append(f"     Suggested include: include {unincluded_journal}")
                report.append("")
        else:
            report.append("✅ All journal files are properly included")
            report.append("")

        # Orphaned files
        if not self.skip_orphan_check:
            if self.orphaned_files:
                report.append("ORPHANED FILES (exist but not referenced)")
                report.append("-" * 40)

                # Group orphaned files by directory for better organization
                orphaned_by_dir = defaultdict(list)
                for orphaned_file in sorted(self.orphaned_files):
                    orphaned_by_dir[orphaned_file.parent].append(orphaned_file)

                for directory in sorted(orphaned_by_dir.keys()):
                    report.append(f"  Directory: {directory}")
                    for orphaned_file in orphaned_by_dir[directory]:
                        report.append(f"    📄 {orphaned_file.name}")
                    report.append("")
            else:
                report.append("✅ No orphaned files found in referenced directories")
                report.append("")
        else:
            report.append("⏭️  Orphaned files check skipped (disabled)")
            report.append("")

        # File references detail
        if self.file_references and self.verbose:
            report.append("DETAILED FILE REFERENCES")
            report.append("-" * 40)
            for file_path, references in sorted(self.file_references.items()):
                status = "✅ EXISTS" if file_path.exists() else "❌ MISSING"
                report.append(f"  {status} {file_path}")
                for journal_path, line_num in references:
                    report.append(f"    Referenced in: {journal_path}:{line_num}")
                report.append("")

        # Invalid filename issues
        if self.invalid_date_files:
            report.append("INVALID FILENAMES")
            report.append("-" * 40)
            for bad_file, journal_path, line_num, reason in sorted(self.invalid_date_files):
                report.append(f"  ❌ {bad_file}")
                report.append(f"     Reason: {reason}")
                report.append(f"     Referenced in: {journal_path}:{line_num}")
                report.append("")
        else:
            report.append("✅ All referenced filenames have valid formats and dates")
            report.append("")

        # Git mode indicator
        if self.git_mode:
            report.append("🔧 Git pre-commit hook mode enabled")
            report.append("")

        report.append("=" * 80)
        report.append("VALIDATION COMPLETE")
        report.append("=" * 80)

        return "\n".join(report)

    def validate(self) -> bool:
        """
        Perform complete validation of the hledger journal system.

        Returns:
            True if validation passed (no issues found), False otherwise
        """
        self.log(f"Starting validation of hledger journal: {self.main_journal_path}")

        if not self.main_journal_path.exists():
            self.log(f"Main journal file not found: {self.main_journal_path}", "ERROR")
            return False

        # Parse all journal files recursively
        self.parse_journal_file(self.main_journal_path)

        # Validate file references
        self.validate_file_references()

        # Validate filenames meet the YYMMDD format
        self.validate_filenames()

        # Validate journal includes
        self.validate_journal_includes()

        # Find orphaned files
        self.find_orphaned_files()

        # Determine validation success
        has_missing_files = len(self.missing_files) > 0
        has_unincluded_journals = len(self.unincluded_journals) > 0
        has_orphaned_files = len(self.orphaned_files) > 0 if not self.skip_orphan_check else False

        # Return True if no issues found
        return not (has_missing_files or has_unincluded_journals or has_orphaned_files)


def install_git_hook(journal_file: str) -> bool:
    """
    Install this script as a git pre-commit hook.

    Args:
        journal_file: Path to the main journal file

    Returns:
        True if installation was successful
    """
    try:
        # Get git repository root
        result = subprocess.run(
            ['git', 'rev-parse', '--show-toplevel'],
            capture_output=True,
            text=True,
            check=True
        )
        git_root = Path(result.stdout.strip())

        # Create hooks directory if it doesn't exist
        hooks_dir = git_root / '.git' / 'hooks'
        hooks_dir.mkdir(exist_ok=True)

        # Path to the pre-commit hook
        hook_path = hooks_dir / 'pre-commit'

        # Get the absolute path to this script
        script_path = Path(__file__).resolve()
        journal_path = Path(journal_file).resolve()

        # Create the hook content
        hook_content = f"""#!/bin/bash
# hledger journal validation pre-commit hook
# Auto-generated by hledger validator

echo "Running hledger journal validation..."
python3 "{script_path}" --git-hook "{journal_path}"

if [ $? -ne 0 ]; then
    echo "❌ hledger validation failed. Commit aborted."
    echo "Fix the issues above and try committing again."
    exit 1
fi

echo "✅ hledger validation passed."
"""

        # Write the hook
        with open(hook_path, 'w') as f:
            f.write(hook_content)

        # Make it executable
        hook_path.chmod(0o755)

        print(f"✅ Git pre-commit hook installed successfully!")
        print(f"Hook location: {hook_path}")
        print(f"Journal file: {journal_path}")
        print("\nThe hook will now run automatically before each commit.")

        return True

    except subprocess.CalledProcessError:
        print("❌ Error: Not in a git repository")
        return False
    except Exception as e:
        print(f"❌ Error installing git hook: {e}")
        return False


def main():
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(
        description="Validate hledger journal file references against filesystem and ensure proper includes",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python hledger_validator.py journal.hledger
  python hledger_validator.py -v /path/to/main.hledger
  python hledger_validator.py --report-only journal.hledger > report.txt
  python hledger_validator.py --skip-orphan-check journal.hledger
  python hledger_validator.py --git-hook journal.hledger
  python hledger_validator.py --install-git-hook journal.hledger
        """
    )

    parser.add_argument(
        'journal_file',
        help='Path to the main hledger journal file'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )

    parser.add_argument(
        '-r', '--report-only',
        action='store_true',
        help='Only output the final report (suppress logging)'
    )

    parser.add_argument(
        '--skip-orphan-check',
        action='store_true',
        help='Skip checking for orphaned files (only validate that referenced files exist)'
    )

    parser.add_argument(
        '--skip-filename-check',
        action='store_true',
        help='Skip checking for filenames are correctly formatted (YYYMMDD)'
    )

    parser.add_argument(
        '--git-hook',
        action='store_true',
        help='Run in git pre-commit hook mode (only show errors/warnings)'
    )

    parser.add_argument(
        '--install-git-hook',
        action='store_true',
        help='Install this script as a git pre-commit hook'
    )

    parser.add_argument(
        '--version',
        action='version',
        version='hledger Journal Validator 2.0.0'
    )

    args = parser.parse_args()

    # Handle git hook installation
    if args.install_git_hook:
        success = install_git_hook(args.journal_file)
        sys.exit(0 if success else 1)

    # Initialize validator
    validator = HledgerValidator(
        args.journal_file,
        verbose=args.verbose and not args.report_only,
        skip_orphan_check=args.skip_orphan_check,
        git_mode=args.git_hook
    )

    try:
        # Perform validation
        success = validator.validate()

        # Generate and display report
        if not args.git_hook or not success:
            # Always show report if not in git mode, or if validation failed in git mode
            report = validator.generate_report()
            print(report)

        # In git hook mode, provide specific messaging
        if args.git_hook:
            if success:
                print("✅ All hledger validations passed")
            else:
                print("❌ hledger validation failed - see issues above")

        # Exit with appropriate code
        sys.exit(0 if success else 1)

    except KeyboardInterrupt:
        print("\nValidation interrupted by user", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"Unexpected error during validation: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()

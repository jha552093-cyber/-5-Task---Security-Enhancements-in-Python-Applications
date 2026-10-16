"""
Automated Packaging Script for Final Deliverables.
Packages the complete codebase, test suite, reports, and static analysis outputs
into a clean, self-contained ZIP archive: Secure_Python_Application_Week5.zip.
"""

import os
import sys
import zipfile

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ZIP_OUTPUT = os.path.join(ROOT_DIR, "Secure_Python_Application_Week5.zip")

EXCLUDE_PATTERNS = [
    "__pycache__",
    ".pytest_cache",
    ".git",
    ".coverage",
    ".dev_secret_key",
    ".dev_enc_key",
    "Secure_Python_Application_Week5.zip"
]


def should_exclude(rel_path: str) -> bool:
    for pattern in EXCLUDE_PATTERNS:
        if pattern in rel_path.split(os.sep) or rel_path.endswith(".pyc"):
            return True
    return False


def build_zip():
    print(f"[*] Packaging deliverables into: {ZIP_OUTPUT}")
    file_count = 0
    total_uncompressed_bytes = 0

    with zipfile.ZipFile(ZIP_OUTPUT, "w", zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(ROOT_DIR):
            # Modify dirs in-place to avoid descending into ignored directories
            dirs[:] = [d for d in dirs if d not in ["__pycache__", ".pytest_cache", ".git"]]

            for file in sorted(files):
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, ROOT_DIR)

                if should_exclude(rel_path):
                    continue

                zipf.write(full_path, rel_path)
                file_count += 1
                total_uncompressed_bytes += os.path.getsize(full_path)
                print(f"  + Added: {rel_path}")

    zip_size = os.path.getsize(ZIP_OUTPUT)
    print("\n" + "=" * 60)
    print(f"[+] Package Created Successfully: {os.path.basename(ZIP_OUTPUT)}")
    print(f"[+] Total Files Packaged:        {file_count}")
    print(f"[+] Uncompressed Size:           {total_uncompressed_bytes / 1024:.2f} KB")
    print(f"[+] Compressed ZIP Size:         {zip_size / 1024:.2f} KB")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    build_zip()

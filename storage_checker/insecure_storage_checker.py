# storage_checker/insecure_storage_checker.py

import os
import re

# Patterns to detect insecure storage practices
PATTERNS = {
    "SharedPreferences in MODE_WORLD_READABLE": r"MODE_WORLD_READABLE",
    "SharedPreferences in MODE_WORLD_WRITABLE": r"MODE_WORLD_WRITABLE",
    "Writing sensitive data to external storage": r"getExternalStorageDirectory\(\)",
    "Hardcoded sensitive info in files": r"(password|apikey|secret).*="
}

def check_insecure_storage(decompiled_path):
    findings = []

    for root, _, files in os.walk(decompiled_path):
        for file in files:
            if file.endswith(".xml") or file.endswith(".java") or file.endswith(".kt") or file.endswith(".smali"):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', errors='ignore') as f:
                        content = f.read()

                        for issue, pattern in PATTERNS.items():
                            matches = re.findall(pattern, content, flags=re.IGNORECASE)
                            if matches:
                                findings.append((file_path, issue, len(matches)))
                except Exception as e:
                    print(f" Error checking storage in {file_path}: {e}")

    # Format the report
    if not findings:
        return " No insecure data storage practices detected.\n"

    report = " Insecure Data Storage Findings:\n"
    for file_path, issue, count in findings:
        report += f"     {issue} ({count} occurrences) in {file_path}\n"

    return report

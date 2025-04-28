# static_code_analysis/scanner.py

import os
import re

# Patterns to search for (common insecure coding practices)
PATTERNS = {
    "Hardcoded API Key": r"(?i)(api[_-]?key\s*=\s*['\"][A-Za-z0-9_\-]{16,}['\"])",
    "Hardcoded Secret": r"(?i)(secret[_-]?key\s*=\s*['\"][A-Za-z0-9_\-]{16,}['\"])",
    "Hardcoded Password": r"(?i)(password\s*=\s*['\"][^'\"]+['\"])",
    "Hardcoded Access Token": r"(?i)(access[_-]?token\s*=\s*['\"][A-Za-z0-9_\-]{16,}['\"])",
    "Usage of WebView with JavaScript Enabled": r"(setJavaScriptEnabled\s*\(\s*true\s*\))",
    "Weak Encryption (ECB Mode)": r"(?i)(AES.*ECB)",
    "Potential SQL Injection Risk": r"(\"SELECT.*\" \+)"
}

def scan_source_code(decompiled_path):
    findings = []

    for root, _, files in os.walk(decompiled_path):
        for file in files:
            if file.endswith(".java") or file.endswith(".kt") or file.endswith(".smali"):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', errors='ignore') as f:
                        content = f.read()

                        for issue, pattern in PATTERNS.items():
                            matches = re.findall(pattern, content)
                            if matches:
                                findings.append((file_path, issue, len(matches)))
                except Exception as e:
                    print(f"❌ Error scanning {file_path}: {e}")

    # Format the report
    if not findings:
        return "✅ No obvious static code vulnerabilities detected.\n"

    report = "🔹 Static Code Vulnerabilities Found:\n"
    for file_path, issue, count in findings:
        report += f"    ❗ {issue} ({count} occurrences) in {file_path}\n"

    return report

# main.py

import os
from reverse_engineering.apk_decompiler import decompile_apk
from permissions_api_check.permission_checker import check_permissions
from static_code_analysis.scanner import scan_source_code
from storage_checker.insecure_storage_checker import check_insecure_storage

def create_reports_folder():
    if not os.path.exists('reports'):
        os.makedirs('reports')

def main():
    print("\n Mobile App Security Auditor\n")
    apk_path = input("[+] Enter path to APK file: ").strip()

    if not os.path.isfile(apk_path):
        print(" Error: APK file not found!")
        return

    create_reports_folder()

    print("\n Step 1: Decompiling APK...")
    decompiled_path = decompile_apk(apk_path)

    if not decompiled_path:
        print(" Error during APK decompilation.")
        return

    print("\n Step 2: Checking Permissions & API Security...")
    permissions_report = check_permissions(decompiled_path)

    print("\n Step 3: Static Code Analysis...")
    static_analysis_report = scan_source_code(decompiled_path)

    print("\n Step 4: Insecure Data Storage Detection...")
    storage_report = check_insecure_storage(decompiled_path)

    print("\n Generating final report...")

    report_path = os.path.join("reports", "audit_report.txt")
    with open(report_path, "w",encoding="utf-8") as report:
        report.write(" Mobile App Security Audit Report\n")
        report.write("===============================\n\n")
        
        report.write(" Permissions and API Security Check:\n")
        report.write(permissions_report + "\n\n")

        report.write(" Static Code Analysis:\n")
        report.write(static_analysis_report + "\n\n")

        report.write(" Insecure Data Storage Check:\n")
        report.write(storage_report + "\n\n")

    print(f"\n Security Audit Completed: {report_path}")

if __name__ == "__main__":
    main()

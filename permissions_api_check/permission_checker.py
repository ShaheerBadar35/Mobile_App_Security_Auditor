# permissions_api_check/permission_checker.py

import os
import re
from xml.etree import ElementTree as ET

# List of dangerous permissions based on Android documentation
DANGEROUS_PERMISSIONS = [
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.GET_ACCOUNTS",
    "android.permission.READ_PHONE_STATE",
    "android.permission.CALL_PHONE",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
]

def check_permissions(decompiled_path):
    manifest_path = os.path.join(decompiled_path, "AndroidManifest.xml")
    
    if not os.path.exists(manifest_path):
        return " AndroidManifest.xml not found. Cannot check permissions."

    try:
        permissions_found = []
        dangerous_found = []
        insecure_apis = []

        # Parse the AndroidManifest.xml
        tree = ET.parse(manifest_path)
        root = tree.getroot()

        # Android XML namespace
        namespace = {'android': 'http://schemas.android.com/apk/res/android'}

        for elem in root.iter("uses-permission"):
            permission = elem.attrib.get('{http://schemas.android.com/apk/res/android}name')
            if permission:
                permissions_found.append(permission)
                if permission in DANGEROUS_PERMISSIONS:
                    dangerous_found.append(permission)

        # Search for any insecure API endpoints (http:// instead of https://)
        for root_dir, _, files in os.walk(decompiled_path):
            for file in files:
                if file.endswith(".xml") or file.endswith(".smali") or file.endswith(".java"):
                    file_path = os.path.join(root_dir, file)
                    with open(file_path, "r", errors="ignore") as f:
                        content = f.read()
                        insecure_endpoints = re.findall(r'http://[^\s\'"]+', content)
                        insecure_apis.extend(insecure_endpoints)

        # Format report
        report = ""

        report += "🔹 Permissions Requested:\n"
        for p in permissions_found:
            report += f"    - {p}\n"

        report += "\n Dangerous Permissions Detected:\n"
        if dangerous_found:
            for dp in dangerous_found:
                report += f"     {dp}\n"
        else:
            report += "    No dangerous permissions detected.\n"

        report += "\n Insecure API Endpoints (HTTP URLs) Found:\n"
        if insecure_apis:
            for api in insecure_apis:
                report += f"     {api}\n"
        else:
            report += "     No insecure API endpoints detected.\n"

        return report

    except Exception as e:
        return f" Error analyzing permissions: {e}"

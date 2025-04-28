# reverse_engineering/apk_decompiler.py

import os
import subprocess
import shutil

def decompile_apk(apk_path):
    output_dir = os.path.join("reverse_engineering", "decompiled_apps")
    app_name = os.path.basename(apk_path).replace(".apk", "")
    decompiled_path = os.path.join(output_dir, app_name)

    try:
        # Create output directory if it doesn't exist
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        # If decompiled path already exists, delete it to re-decompile
        if os.path.exists(decompiled_path):
            shutil.rmtree(decompiled_path)

        print(f"[+] Decompiling {apk_path} ...")
        
        # Using apktool to decompile
        subprocess.run(["apktool", "d", apk_path, "-o", decompiled_path, "-f"], check=True)

        print(f"[+] APK decompiled to: {decompiled_path}")
        return decompiled_path

    except subprocess.CalledProcessError as e:
        print(f"❌ Decompilation failed: {e}")
        return None
    except Exception as e:
        print(f"❌ Error: {e}")
        return None

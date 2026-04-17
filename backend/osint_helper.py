import subprocess
import os
import json
import re
import time

# Path to the Sherlock executable in the virtual environment
SHERLOCK_PATH = os.path.join(os.getcwd(), "sherlock_venv", "bin", "sherlock")

def run_sherlock(username):
    """
    Runs Sherlock OSINT tool for a given username.
    Returns a list of found social media profiles.
    """
    # 1. Validation to prevent command injection
    if not re.match(r'^[a-zA-Z0-9._-]+$', username):
        print(f"⚠️ Invalid username format: {username}")
        return []

    if not os.path.exists(SHERLOCK_PATH):
        windows_path = os.path.join(os.getcwd(), "sherlock_venv", "Scripts", "sherlock.exe")
        executable = windows_path if os.path.exists(windows_path) else "sherlock"
    else:
        executable = SHERLOCK_PATH

    print(f"🔍 Running Sherlock OSINT for: {username}")
    
    # 2. Use unique report file to avoid collisions
    report_file = f"report_{username}_{int(time.time())}.json"
    
    try:
        # Run Sherlock and output to unique JSON file
        # --json: output results to a json file
        # --timeout 1: limit wait time per site for speed
        subprocess.run(
            [executable, username, "--json", report_file, "--timeout", "1"],
            capture_output=True,
            text=True,
            check=False
        )
        
        if os.path.exists(report_file):
            with open(report_file, "r") as f:
                data = json.load(f)
            
            os.remove(report_file)
            
            profiles = []
            for site, info in data.items():
                if info.get("status") == "CLAIMED":
                    profiles.append({
                        "platform": site,
                        "url": info.get("url_user")
                    })
            return profiles
        else:
            print(f"⚠️ Sherlock report {report_file} not found.")
            return []

    except Exception as e:
        print(f"❌ Sherlock Error: {e}")
        # Final cleanup attempt
        if os.path.exists(report_file):
            os.remove(report_file)
        return []

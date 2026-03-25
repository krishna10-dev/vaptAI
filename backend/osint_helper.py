import subprocess
import os
import json

# Path to the Sherlock executable in the virtual environment
SHERLOCK_PATH = os.path.join(os.getcwd(), "sherlock_venv", "bin", "sherlock")

def run_sherlock(username):
    """
    Runs Sherlock OSINT tool for a given username.
    Returns a list of found social media profiles.
    """
    if not os.path.exists(SHERLOCK_PATH):
        # Fallback for Windows if bin/sherlock doesn't exist (might be Scripts/sherlock)
        windows_path = os.path.join(os.getcwd(), "sherlock_venv", "Scripts", "sherlock.exe")
        executable = windows_path if os.path.exists(windows_path) else "sherlock"
    else:
        executable = SHERLOCK_PATH

    print(f"🔍 Running Sherlock OSINT for: {username}")
    
    try:
        # Run Sherlock and output to JSON
        # --json: output results to a json file
        # --timeout 1: limit wait time per site for speed
        output_file = f"osint_{username}.json"
        
        # Note: Sherlock creates the file automatically with --json
        # Using subprocess to run the command
        process = subprocess.run(
            [executable, username, "--json", "report.json", "--timeout", "1"],
            capture_output=True,
            text=True
        )
        
        # Check if report.json was created
        if os.path.exists("report.json"):
            with open("report.json", "r") as f:
                data = json.load(f)
            
            # Cleanup
            os.remove("report.json")
            
            # Format results
            profiles = []
            for site, info in data.items():
                if info.get("status") == "CLAIMED":
                    profiles.append({
                        "platform": site,
                        "url": info.get("url_user")
                    })
            return profiles
        else:
            print("⚠️ Sherlock report.json not found.")
            return []

    except Exception as e:
        print(f"❌ Sherlock Error: {e}")
        return []

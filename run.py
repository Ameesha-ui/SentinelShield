"""
SentinelShield - Application Launcher & Control Script
Provides quick commands to launch the server, run the attack test battery,
or execute the pytest test suite.
"""

import sys
import subprocess
import os


def print_banner():
    print("""
========================================================================
   ____             __  _            __  ____  __     _      __    __
  / __/___  ___  __/ /_(_)__  ___   / / / __/ / /    (_)__  / /___/ /
 _\\ \\/ -_)/ _ \\/ _  / / / _ \\/ -_) / / _\\ \\/ _  /    / / -_)/ // _  / 
/___/\\__/ /_//_/\\_,_/_/_/_//_/\\__/ /_/ /___/\\_,_/  _/_/ \\__/_/ \\_,_/  
                                                 /___/                
========================================================================
 Web Application Firewall & Intrusion Detection Practical Lab
========================================================================
    """)


def main():
    print_banner()
    if len(sys.argv) > 1:
        cmd = sys.argv[1].lower()
        if cmd == "test":
            print("[*] Running unit test suite with pytest...")
            subprocess.run([sys.executable, "-m", "pytest", "tests", "-v"])
            return
        elif cmd == "simulate":
            print("[*] Running attack test battery & generating practical report...")
            subprocess.run([sys.executable, "simulator/generate_report.py"])
            return
        elif cmd == "help":
            print("Usage: python run.py [server|test|simulate]")
            print("  server   - Launch protected application and SOC dashboard (default)")
            print("  test     - Run pytest unit tests on WAF engine")
            print("  simulate - Run attack simulator and generate evaluation report")
            return

    # Default: Start server
    print("[*] Starting SentinelShield Protected Server & SOC Dashboard...")
    print("[*] Web Application: http://127.0.0.1:5000")
    print("[*] SOC Dashboard:   http://127.0.0.1:5000/dashboard")
    print("[*] Press Ctrl+C to terminate.")
    print("-" * 72)
    from app import app
    app.run(host="127.0.0.1", port=5000, debug=True)


if __name__ == "__main__":
    main()


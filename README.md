# 🛡️ Keylogger Detection & Response Agent

A **Windows-based Python cybersecurity project** that detects, quarantines, and terminates suspicious keylogger-like processes using **heuristics**, **registry checks**, and **file handle monitoring**.  
It includes both a **console agent** and an interactive **Tkinter GUI** for live demonstrations and educational use.

---

## ⚠️ Legal & Safety Disclaimer

This project is for **educational and portfolio use only**.  
The included `keylogger_test.py` is a **benign lab simulator** that mimics keylogger behavior (it logs to a visible text file, not stealthily).  
Do **not** use any form of keylogger or detection code on systems you don’t own or without permission.

Always test in an **isolated virtual machine (VM)** snapshot — never on a production or host system.

---

## 🧩 Project Overview

| Component | Description |

|------------|--------------|
| **`detector_gui.py`** | Full-featured Tkinter GUI to scan, detect, quarantine, and log suspicious processes. |
| **`detector_agent.py`** | Console-only background scanner (same detection engine). |
| **`keylogger_test.py`** | Benign test script to simulate keylogging behavior for demonstrations. |
| **`screenshots/`** | Folder containing captured demo images. |
| **`quarantine/`** | Automatically created directory for quarantined executables. (gitignored for safety) |
| **`demo_instructions.txt`** | Walkthrough script for recording or presentation demos. |

---

## 🧠 Detection Logic (Heuristic Overview)

- **Process Path & Name Heuristics**  
  Detects executables with suspicious keywords such as `keylog`, `keyboard`, or those located under `AppData`, `Temp`, or `Users\Public`.

- **File Handle Analysis**  
  Flags processes that open `.txt` or `.log` files in sensitive directories.

- **Registry Persistence Check**  
  Scans `HKCU` and `HKLM` “Run” keys for suspicious autorun entries.

- **Network Activity Awareness**  
  Adds suspicion score for outbound network connections.

- **Quarantine & Kill**  
  Suspicious binaries are automatically moved to a quarantine folder and the process is terminated.

---

## ⚙️ Setup Instructions

### 1️⃣ Prerequisites

Ensure you’re using **Python 3.10+** on your Windows VM.

Install required modules:
```bash
python -m pip install --upgrade pip
pip install psutil pywin32 wmi pynput pyscreenshot pillow
```

### 2️⃣ Folder Layout

Your C:\KeylogDetector folder should look like this:

C:\KeylogDetector
│
├── detector_gui.py

├── detector_agent.py

├── keylogger_test.py

├── demo_instructions.txt

├── screenshots/

│   ├── screenshot_detector_detected.png
│   ├── screenshot_quarantine_folder.png
│   └── ...
└── quarantine/      # (auto-created, gitignored)

### 🧪 Demo Steps (Lab Workflow)

💡 Make sure your VM snapshot is saved before running the test.

🧩 Step 1 — Run the Test Keylogger
```bash
cd C:\KeylogDetector
python keylogger_test.py
```

Open Notepad and type a few words.

Check C:\Users\Public\keylog_test.txt — your keystrokes appear there.

### 🧩 Step 2 — Launch the Detector GUI

Open Command Prompt as Administrator

Navigate to your folder:
```bash
cd C:\KeylogDetector
```

Run:
```bash
python detector_gui.py
```

### 🧩 Step 3 — Start Scanning

Click Start Scanning

After a few seconds, detection logs will appear:
```bash
DETECTED PID=xxxx NAME=python.exe SCORE=8
  - open log file C:\Users\Public\keylog_test.txt
  - name contains keylog
Successfully quarantined to C:\KeylogDetector\quarantine\python.exe_...
```         

### 🧩 Step 4 — Check Quarantine

Click Open Quarantine Folder

Verify a quarantined file appears inside (e.g., python.exe_1697551820).

### 🧩 Step 5 — Verify Keylogger Termination

The keylogger CMD window should close automatically.

Check Task Manager — no extra python.exe processes running.

keylog_test.txt should stop updating.

### 🧩 Step 6 — Capture GUI Screenshot (Optional)

In the GUI, click Take Screenshot

Saved automatically to:
```bash
C:\KeylogDetector\screenshots\gui_screenshot_<timestamp>.png
```

### 🧩 Step 7 — Stop Scanning & Cleanup

Click Stop Scanning

Close the GUI

Optionally delete the quarantined file and restore VM snapshot.

### 🧰 Example Commands Summary
# 1. Run benign keylogger
python keylogger_test.py

# 2. Run detector GUI as admin
python detector_gui.py

# 3. (Optional) Manual scan in GUI
# 4. (Optional) Take Screenshot
# 5. Stop Scanning and exit

### 👩‍💻 Author

Mugeha — Cybersecurity Enthusiast & Future Pen Tester
Focused on Application Security Engineering, Threat Detection, and Secure Systems Development.
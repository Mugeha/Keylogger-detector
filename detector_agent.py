# detector_agent.py — your keylogger detection tool
# Safe educational use only.
import psutil, time, os, shutil
import winreg
from datetime import datetime

SUSPICIOUS_PATH_KEYWORDS = ["\\appdata\\", "\\roaming\\", "\\temp\\", "\\programdata\\", "\\users\\public\\"]
SUSPICIOUS_FILENAME_KEYWORDS = ["keylog", "keylogger", "keyboard", "keystrokes"]
QUARANTINE_DIR = r"C:\KeylogDetector\quarantine"

os.makedirs(QUARANTINE_DIR, exist_ok=True)

def check_run_keys():
    findings = []
    run_keys = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run")
    ]
    for hive, sub in run_keys:
        try:
            with winreg.OpenKey(hive, sub) as key:
                i = 0
                while True:
                    try:
                        name, val, _ = winreg.EnumValue(key, i)
                        for kw in SUSPICIOUS_FILENAME_KEYWORDS:
                            if kw in val.lower():
                                findings.append(f"RunKey suspicious: {name} -> {val}")
                        i += 1
                    except OSError:
                        break
        except Exception:
            continue
    return findings

def score_process(proc):
    score = 0
    reasons = []
    try:
        exe = proc.exe().lower()
    except Exception:
        exe = ""
    name = proc.name().lower()

    for kw in SUSPICIOUS_PATH_KEYWORDS:
        if kw in exe:
            score += 2
            reasons.append(f"path contains {kw}")

    for kw in SUSPICIOUS_FILENAME_KEYWORDS:
        if kw in name or kw in exe:
            score += 3
            reasons.append(f"name contains {kw}")

    try:
        for f in proc.open_files():
            fp = f.path.lower()
            if fp.endswith((".txt", ".log")):
                score += 2
                reasons.append(f"open log file {fp}")
            for kw in SUSPICIOUS_FILENAME_KEYWORDS:
                if kw in fp:
                    score += 3
                    reasons.append(f"open suspicious file {fp}")
    except Exception:
        pass

    try:
        cons = proc.connections(kind="inet")
        outbound = [c for c in cons if c.raddr]
        if outbound:
            score += 1
            reasons.append(f"outbound connections {len(outbound)}")
    except Exception:
        pass

    return score, reasons, exe

def quarantine_process(proc, exe_path):
    try:
        base = os.path.basename(exe_path)
        dst = os.path.join(QUARANTINE_DIR, f"{base}_{int(time.time())}")
        if os.path.exists(exe_path):
            shutil.move(exe_path, dst)
        proc.kill()
        return True, dst
    except Exception as e:
        return False, str(e)

def scan_and_detect(score_threshold=4):
    detections = []
    print(f"[{datetime.now()}] Starting scan...")

    reg_findings = check_run_keys()
    for r in reg_findings:
        print("REG:", r)

    for p in psutil.process_iter(['pid', 'name']):
        try:
            score, reasons, exe = score_process(p)
            if score >= score_threshold:
                detections.append((p.pid, p.name(), exe, score, reasons))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    for pid, name, exe, score, reasons in detections:
        print(f"[DETECTED] PID={pid} NAME={name} SCORE={score}")
        for r in reasons:
            print("  -", r)
        try:
            proc = psutil.Process(pid)
            ok, info = quarantine_process(proc, exe)
            if ok:
                print(f"  -> quarantined executable to {info} and killed PID {pid}")
            else:
                print(f"  -> failed to quarantine: {info}")
        except Exception as e:
            print("  -> error during containment:", e)

    if not detections:
        print("No suspicious processes found.")
    print(f"[{datetime.now()}] Scan complete.\n")

if __name__ == "__main__":
    try:
        while True:
            scan_and_detect()
            time.sleep(10)
    except KeyboardInterrupt:
        print("Agent stopped by user.")

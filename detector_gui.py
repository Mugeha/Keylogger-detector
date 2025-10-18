# detector_gui.py — Heuristic Keylogger Detector with simple Tkinter GUI
# Lab use only. Make sure you run in an isolated VM snapshot.
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading, time, os, shutil
import psutil, winreg
from datetime import datetime

SUSPICIOUS_PATH_KEYWORDS = ["\\appdata\\", "\\roaming\\", "\\temp\\", "\\programdata\\", "\\users\\public\\"]
SUSPICIOUS_FILENAME_KEYWORDS = ["keylog", "keylogger", "keyboard", "keystrokes"]
BASE_DIR = r"C:\KeylogDetector"
QUARANTINE_DIR = os.path.join(BASE_DIR, "quarantine")
SCREENSHOT_DIR = os.path.join(BASE_DIR, "screenshots")
os.makedirs(QUARANTINE_DIR, exist_ok=True)
os.makedirs(SCREENSHOT_DIR, exist_ok=True)

SCAN_INTERVAL = 10  # seconds

# ---------- Detection logic (same as console version, wrapped for GUI) ----------
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
                            if kw in str(val).lower():
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

def quarantine_process(pid, exe_path):
    try:
        base = os.path.basename(exe_path) or f"proc_{pid}"
        dst = os.path.join(QUARANTINE_DIR, f"{base}_{int(time.time())}")
        if os.path.exists(exe_path):
            shutil.move(exe_path, dst)
        p = psutil.Process(pid)
        p.kill()
        return True, dst
    except Exception as e:
        return False, str(e)

def scan_once(score_threshold=4):
    output = []
    reg_findings = check_run_keys()
    for r in reg_findings:
        output.append(("REG", r))
    for p in psutil.process_iter(['pid','name']):
        try:
            score, reasons, exe = score_process(p)
            if score >= score_threshold:
                output.append(("DETECT", p.pid, p.name(), exe, score, reasons))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return output

# ---------- GUI & threading ----------
class DetectorApp:
    def __init__(self, root):
        self.root = root
        root.title("Keylogger Detector — GUI")
        root.geometry("820x560")
        self.running = False
        self.scan_thread = None

        # Top controls
        top_frame = ttk.Frame(root, padding=8)
        top_frame.pack(side="top", fill="x")

        self.start_btn = ttk.Button(top_frame, text="Start Scanning", command=self.start_scanning)
        self.start_btn.pack(side="left", padx=4)
        self.stop_btn = ttk.Button(top_frame, text="Stop Scanning", command=self.stop_scanning, state="disabled")
        self.stop_btn.pack(side="left", padx=4)

        ttk.Button(top_frame, text="Manual Scan", command=self.manual_scan).pack(side="left", padx=4)
        ttk.Button(top_frame, text="Open Quarantine Folder", command=self.open_quarantine).pack(side="left", padx=4)
        ttk.Button(top_frame, text="Take Screenshot", command=self.take_screenshot).pack(side="left", padx=4)

        # Middle: detection log and actions
        mid_frame = ttk.Frame(root, padding=8)
        mid_frame.pack(side="top", fill="both", expand=True)

        left_col = ttk.Frame(mid_frame)
        left_col.pack(side="left", fill="both", expand=True)

        ttk.Label(left_col, text="Detections / Log:").pack(anchor="w")
        self.log_box = scrolledtext.ScrolledText(left_col, width=70, height=25)
        self.log_box.pack(fill="both", expand=True)

        right_col = ttk.Frame(mid_frame, width=220)
        right_col.pack(side="left", fill="y", padx=6)

        ttk.Label(right_col, text="Quarantine:").pack(anchor="w")
        self.quar_list = tk.Listbox(right_col, height=12, width=40)
        self.quar_list.pack(fill="y")
        ttk.Button(right_col, text="Refresh", command=self.refresh_quarantine).pack(fill="x", pady=6)
        ttk.Button(right_col, text="Open Selected", command=self.open_selected_quarantine).pack(fill="x")

        # Status bar
        self.status_var = tk.StringVar(value="Stopped")
        status = ttk.Label(root, textvariable=self.status_var, relief="sunken", anchor="w")
        status.pack(side="bottom", fill="x")

        self.refresh_quarantine()
        self.log("App started. Make sure you are running from an isolated VM snapshot.")

    def log(self, *parts):
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = " ".join(str(p) for p in parts)
        self.log_box.insert("end", f"[{now}] {line}\n")
        self.log_box.see("end")

    def start_scanning(self):
        if self.running:
            return
        self.running = True
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.status_var.set("Running")
        self.scan_thread = threading.Thread(target=self.scan_loop, daemon=True)
        self.scan_thread.start()
        self.log("Background scanning started.")

    def stop_scanning(self):
        if not self.running:
            return
        self.running = False
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.status_var.set("Stopped")
        self.log("Background scanning stopped.")

    def scan_loop(self):
        while self.running:
            results = scan_once()
            self.process_results(results)
            time.sleep(SCAN_INTERVAL)

    def manual_scan(self):
        self.log("Manual scan triggered.")
        results = scan_once()
        self.process_results(results)

    def process_results(self, results):
        if not results:
            self.log("No suspicious processes found.")
            return
        for item in results:
            if item[0] == "REG":
                _, msg = item
                self.log("Registry:", msg)
            else:
                _, pid, name, exe, score, reasons = item
                self.log(f"DETECTED PID={pid} NAME={name} SCORE={score}")
                for r in reasons:
                    self.log("  -", r)
                ok, info = quarantine_process(pid, exe)
                if ok:
                    self.log(f"Successfully quarantined to {info} and terminated PID {pid}")
                else:
                    self.log(f"Failed to quarantine: {info}")
                self.refresh_quarantine()

    def refresh_quarantine(self):
        self.quar_list.delete(0, "end")
        try:
            items = os.listdir(QUARANTINE_DIR)
            for it in items:
                self.quar_list.insert("end", it)
        except Exception:
            pass

    def open_quarantine(self):
        os.startfile(QUARANTINE_DIR)

    def open_selected_quarantine(self):
        sel = self.quar_list.curselection()
        if not sel:
            messagebox.showinfo("Select item", "Please select a quarantined file.")
            return
        fname = self.quar_list.get(sel[0])
        path = os.path.join(QUARANTINE_DIR, fname)
        os.startfile(path)

    def take_screenshot(self):
        # simple screenshot of the GUI area: capture using the built-in tkinter method
        try:
            import pyscreenshot as ImageGrab
        except Exception:
            self.log("Screenshot requires 'pyscreenshot'. Installing...")
            try:
                import subprocess, sys
                subprocess.check_call([sys.executable, "-m", "pip", "install", "pyscreenshot"])
                import pyscreenshot as ImageGrab
            except Exception as e:
                self.log("Failed to install pyscreenshot:", e)
                return
        bbox = None  # full screen
        img = ImageGrab.grab(bbox=bbox)
        fname = os.path.join(SCREENSHOT_DIR, f"gui_screenshot_{int(time.time())}.png")
        img.save(fname)
        self.log("Saved screenshot to", fname)
        os.startfile(SCREENSHOT_DIR)

if __name__ == "__main__":
    root = tk.Tk()
    app = DetectorApp(root)
    root.mainloop()

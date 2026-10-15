"""Native local path selection in an isolated Tk main thread."""

import json
import sys
import tkinter as tk
from tkinter import filedialog


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)
    try:
        picker = filedialog.askdirectory if sys.argv[1] == "directory" else filedialog.askopenfilename
        path = picker(parent=root, title="选择检材文件夹" if sys.argv[1] == "directory" else "选择检材文件")
        print(json.dumps({"path": path}, ensure_ascii=False))
    finally:
        root.destroy()


if __name__ == "__main__":
    main()

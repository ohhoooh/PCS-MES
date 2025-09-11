import tkinter as tk
from gui import MESQuerySystem

def main():
    """主程序入口"""
    root = tk.Tk()
    app = MESQuerySystem(root)
    root.mainloop()

if __name__ == "__main__":
    main()

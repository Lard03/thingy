import customtkinter as ctk
from gui.gui import MemScanUI

def main():
    root = ctk.CTk()
    app = MemScanUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
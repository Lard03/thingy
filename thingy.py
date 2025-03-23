import pymem
import pymem.process
import pygetwindow as gw
import win32process
import customtkinter as ctk
import tkinter as tk
import threading
from pymem.exception import PymemError

class MemScan:
    def __init__(self, root):
        self.root = root
        self.root.title("Memory Scanner")
        self.root.geometry("1000x700")
        self.root.configure(bg="#1e1e2e")
        
        self.pm = None
        self.scanned_addresses = []
        self.is_scanning = False
        
        ctk.set_appearance_mode("dark")
        
        main_frame = ctk.CTkFrame(root)
        main_frame.pack(pady=20, padx=20, fill=tk.BOTH, expand=True)
        
        left_frame = ctk.CTkFrame(main_frame)
        left_frame.pack(side=tk.LEFT, padx=10, pady=10, fill=tk.Y)
        
        self.process_list = ctk.CTkTextbox(left_frame, width=300, height=400)
        self.process_list.pack(pady=10)
        
        self.select_process_button = ctk.CTkButton(left_frame, text="Select Process", command=self.select_process)
        self.select_process_button.pack(pady=10)
        
        self.refresh_button = ctk.CTkButton(left_frame, text="Refresh", command=self.refresh_process_list)
        self.refresh_button.pack(pady=10)
        
        right_frame = ctk.CTkFrame(main_frame)
        right_frame.pack(side=tk.RIGHT, padx=10, pady=10, fill=tk.BOTH, expand=True)
        
        self.scan_value_entry = ctk.CTkEntry(right_frame, placeholder_text="Value to scan")
        self.scan_value_entry.pack(pady=10, padx=20, fill=tk.X)
        
        self.scan_type_combo = ctk.CTkComboBox(
            right_frame, values=["Integer", "Float"], state="readonly"
        )
        self.scan_type_combo.set("Integer")
        self.scan_type_combo.pack(pady=10, padx=20, fill=tk.X)
        
        button_frame = ctk.CTkFrame(right_frame)
        button_frame.pack(pady=10)
        
        self.scan_button = ctk.CTkButton(button_frame, text="Scan", command=self.start_scan_memory)
        self.scan_button.pack(side=tk.LEFT, padx=5)
        
        self.next_scan_button = ctk.CTkButton(button_frame, text="Next Scan", command=self.next_scan_memory)
        self.next_scan_button.pack(side=tk.LEFT, padx=5)
        
        self.results_list = ctk.CTkTextbox(right_frame, width=400, height=200)
        self.results_list.pack(pady=10, padx=20, fill=tk.BOTH, expand=True)
        
        self.new_value_entry = ctk.CTkEntry(right_frame, placeholder_text="New Value")
        self.new_value_entry.pack(pady=10, padx=20, fill=tk.X)
        
        self.update_button = ctk.CTkButton(right_frame, text="Change Value", command=self.update_value)
        self.update_button.pack(pady=10)
        
        self.status_label = ctk.CTkLabel(right_frame, text="Ready")
        self.status_label.pack(pady=10)
        
        self.get_process_list()
    
    def get_process_list(self):
        self.process_list.delete("1.0", tk.END)
        try:
            self.processes = [(win32process.GetWindowThreadProcessId(win._hWnd)[1], win.title) 
                        for win in gw.getAllWindows() 
                        if win.visible and win.title]
            for pid, title in sorted(self.processes, key=lambda x: x[1]):
                self.process_list.insert(tk.END, f"{title} (PID: {pid})\n")
        except Exception as e:
            self.status_label.configure(text=f"Error: {e}")
    
    def refresh_process_list(self):
        self.get_process_list()
    
    def select_process(self):
        try:
            selected_text = self.process_list.get("sel.first", "sel.last").strip()
            pid_start = selected_text.rfind("PID: ") + 5
            pid = int(selected_text[pid_start:])
            self.pm = pymem.Pymem(pid)
            self.status_label.configure(text=f"Attached to PID {pid}")
        except Exception as e:
            self.status_label.configure(text=f"Selection error: {e}")
    
    def start_scan_memory(self):
        if not self.pm:
            self.status_label.configure(text="No process selected")
            return
        try:
            value = int(self.scan_value_entry.get())
            self.scanned_addresses = []
            self.results_list.delete("1.0", tk.END)
            for address in pymem.process.module_from_name(self.pm.process_handle, self.pm.process_base).lpBaseOfDll:
                try:
                    data = self.pm.read_int(address)
                    if data == value:
                        self.scanned_addresses.append(address)
                        self.results_list.insert(tk.END, f"{hex(address)}\n")
                except:
                    continue
            self.status_label.configure(text=f"Found {len(self.scanned_addresses)} matches")
        except Exception as e:
            self.status_label.configure(text=f"Scan error: {e}")
    
    def next_scan_memory(self):
        if not self.pm or not self.scanned_addresses:
            self.status_label.configure(text="No previous scan results")
            return
        try:
            value = int(self.scan_value_entry.get())
            new_addresses = []
            self.results_list.delete("1.0", tk.END)
            for address in self.scanned_addresses:
                try:
                    data = self.pm.read_int(address)
                    if data == value:
                        new_addresses.append(address)
                        self.results_list.insert(tk.END, f"{hex(address)}\n")
                except:
                    continue
            self.scanned_addresses = new_addresses
            self.status_label.configure(text=f"Refined to {len(self.scanned_addresses)} matches")
        except Exception as e:
            self.status_label.configure(text=f"Next scan error: {e}")
    
    def update_value(self):
        if not self.pm or not self.scanned_addresses:
            self.status_label.configure(text="No scan results to update")
            return
        try:
            new_value = int(self.new_value_entry.get())
            for address in self.scanned_addresses:
                self.pm.write_int(address, new_value)
            self.status_label.configure(text="Values updated successfully")
        except Exception as e:
            self.status_label.configure(text=f"Update error: {e}")

if __name__ == "__main__":
    root = ctk.CTk()
    app = MemScan(root)
    root.mainloop()

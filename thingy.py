import psutil
import pymem
import pygetwindow as gw
import win32process
import customtkinter as ctk
import tkinter as tk
import threading

class memscan:
    def __init__(self, root):
        self.root = root
        self.root.title("Memory Scanner")
        self.root.geometry("1000x900")
        
        self.pm = None
        self.scanned_addresses = []
        
        self.process_list = tk.Listbox(root, width=80, height=15, font=("Helvetica", 18))
        self.process_list.pack(pady=20)
        
        self.refresh_button = ctk.CTkButton(root, text="Refresh", command=self.refresh_process_list, width=200, height=50)
        self.refresh_button.pack(pady=15)
        
        self.scan_value_entry = ctk.CTkEntry(root, placeholder_text="Value to scan", width=400, height=40)
        self.scan_value_entry.pack(pady=15)
        
        self.scan_button = ctk.CTkButton(root, text="Scan", command=self.start_scan_memory, width=200, height=50)
        self.scan_button.pack(pady=15)
        
        self.results_list = tk.Listbox(root, width=80, height=15, font=("Helvetica", 18))
        self.results_list.pack(pady=20)
        
        self.new_value_entry = ctk.CTkEntry(root, placeholder_text="New Value", width=400, height=40)
        self.new_value_entry.pack(pady=15)
        
        self.update_button = ctk.CTkButton(root, text="Change Value", command=self.update_value, width=200, height=50)
        self.update_button.pack(pady=15)
        
        self.status_label = ctk.CTkLabel(root, text="", font=("Helvetica", 16))
        self.status_label.pack(pady=15)
        
        self.get_process_list()
    
    def get_process_list(self):
        processes = []
        for win in gw.getAllWindows():
            if win.visible and win.title:
                try:
                    _, pid = win32process.GetWindowThreadProcessId(win._hWnd)
                    processes.append((pid, win.title))
                except:
                    continue
        
        for pid, title in processes:
            self.process_list.insert(tk.END, f"{title} (PID: {pid})")
            
        self.process_list.bind("<Double-Button-1>", self.select_process)
    
    def refresh_process_list(self):
        self.process_list.delete(0, tk.END)
        self.get_process_list()
    
    def select_process(self, event):
        selection = self.process_list.curselection()
        if not selection:
            return
        selected_text = self.process_list.get(selection[0])
        pid = int(selected_text.split("(PID: ")[1][:-1])
        self.attach_to_process(pid)
        print(f"Selected PID: {pid}")
    
    def attach_to_process(self, pid):
        try:
            self.pm = pymem.Pymem()
            self.pm.open_process_from_id(pid)
            self.status_label.configure(text=f"Attached to PID: {pid}")
        except Exception as e:
            self.status_label.configure(text=f"Error: {e}")
    
    def start_scan_memory(self):
        threading.Thread(target=self.scan_memory).start()
    
    def scan_memory(self):
        if not self.pm:
            self.status_label.configure(text="No process attached.")
            return

        try:
            print("Scanning memory...")
            value_to_scan = self.scan_value_entry.get()
            is_integer = value_to_scan.isdigit()
            value_to_scan = int(value_to_scan) if is_integer else value_to_scan.encode()

            self.scanned_addresses.clear()
            self.results_list.delete(0, tk.END)

            for module in self.pm.list_modules():
                base_address = module.lpBaseOfDll
                size = module.SizeOfImage

                try:
                    memory = self.pm.read_bytes(base_address, size)

                    for i in range(len(memory) - (4 if is_integer else len(value_to_scan))):
                        try:
                            if is_integer:
                                val = int.from_bytes(memory[i:i+4], 'little')
                                if val == value_to_scan:
                                    address = base_address + i
                                    self.scanned_addresses.append(address)
                                    self.results_list.insert(tk.END, f"{hex(address)} -> {val}")
                            else:
                                if memory[i:i+len(value_to_scan)] == value_to_scan:
                                    address = base_address + i
                                    self.scanned_addresses.append(address)
                                    self.results_list.insert(tk.END, f"{hex(address)} -> {value_to_scan.decode()}")
                        except:
                            continue
                except pymem.exception.MemoryReadError:
                    continue

            self.status_label.configure(text=f"Scan completed. Found {len(self.scanned_addresses)} matches.")
        except Exception as e:
            self.status_label.configure(text=f"Error: {e}")

    def update_value(self):
        if not self.pm or not self.scanned_addresses:
            self.status_label.configure(text="No addresses to update.")
            return
        
        try:
            new_value = self.new_value_entry.get()
            is_integer = new_value.isdigit()
            new_value = int(new_value) if is_integer else new_value.encode()

            for address in self.scanned_addresses:
                if is_integer:
                    self.pm.write_int(address, new_value)
                else:
                    self.pm.write_bytes(address, new_value, len(new_value))

            self.status_label.configure(text="Memory updated successfully!")
        except Exception as e:
            self.status_label.configure(text=f"Error: {e}")

if __name__ == "__main__":
    root = ctk.CTk()
    app = memscan(root)
    root.mainloop()
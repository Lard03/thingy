import pymem
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
        self.root.geometry("1000x900")
        
        self.pm = None
        self.scanned_addresses = []
        self.is_scanning = False
        self.is_monitoring = False
        
        self.process_list = tk.Listbox(root, width=80, height=10
        , font=("Helvetica", 18))
        self.process_list.pack(pady=20)
        
        self.refresh_button = ctk.CTkButton(root, text="Refresh", command=self.refresh_process_list, width=200, height=50)
        self.refresh_button.pack(pady=10
        )
        
        self.scan_value_entry = ctk.CTkEntry(root, placeholder_text="Value to scan", width=400, height=40)
        self.scan_value_entry.pack(pady=10
        )
        
        self.scan_type_combo = ctk.CTkComboBox(root, values=["Integer", "Float", "String"], width=200, height=40)
        self.scan_type_combo.set("Integer")
        self.scan_type_combo.pack(pady=10
        )

        button_frame = tk.Frame(root, bg=root["bg"])
        button_frame.pack(pady=10)

        self.scan_button = ctk.CTkButton(button_frame, text="Scan", command=self.start_scan_memory, width=200, height=50)
        self.scan_button.pack(side=tk.LEFT, padx=5)

        self.next_scan_button = ctk.CTkButton(button_frame, text="Next Scan", command=self.next_scan_memory, width=200, height=50)
        self.next_scan_button.pack(side=tk.LEFT, padx=5)
        
        self.results_list = tk.Listbox(root, width=80, height=10
        , font=("Helvetica", 18))
        self.results_list.pack(pady=20)
        
        self.new_value_entry = ctk.CTkEntry(root, placeholder_text="New Value", width=400, height=40)
        self.new_value_entry.pack(pady=10
        )
        
        self.update_button = ctk.CTkButton(root, text="Change Value", command=self.update_value, width=200, height=50)
        self.update_button.pack(pady=10
        )
        
        self.status_label = ctk.CTkLabel(root, text="Ready", font=("Helvetica", 16))
        self.status_label.pack(pady=10
        )

        self.get_process_list()

    def get_process_list(self):
        print("Getting process list...")
        self.process_list.delete(0, tk.END)
        try:
            processes = [(win32process.GetWindowThreadProcessId(win._hWnd)[1], win.title) 
                        for win in gw.getAllWindows() 
                        if win.visible and win.title]
            for pid, title in sorted(processes, key=lambda x: x[1]):
                self.process_list.insert(tk.END, f"{title} (PID: {pid})")
            print("Process list updated.")
        except Exception as e:
            self.status_label.configure(text=f"Error getting processes: {e}")
            print(f"Error getting processes: {e}")
        self.process_list.bind("<Double-Button-1>", self.select_process)

    def refresh_process_list(self):
        print("Refreshing process list...")
        self.close_process()
        self.get_process_list()

    def select_process(self, event):
        if not self.process_list.curselection():
            return
        selected = self.process_list.get(self.process_list.curselection()[0])
        print(f"Selected process: {selected}")
        try:
            pid = int(selected.split("(PID: ")[1][:-1])
            self.attach_to_process(pid)
        except (IndexError, ValueError) as e:
            self.status_label.configure(text=f"Error selecting process: {e}")
            print(f"Error selecting process: {e}")

    def attach_to_process(self, pid):
        print(f"Attaching to process with PID: {pid}")
        self.close_process()
        try:
            self.pm = pymem.Pymem(pid)
            self.status_label.configure(text=f"Attached to PID: {pid}")
            print(f"Successfully attached to PID: {pid}")
            return True
        except PymemError as e:
            self.status_label.configure(text=f"Failed to attach: {e}")
            print(f"Failed to attach: {e}")
            self.pm = None
            return False

    def close_process(self):
        if self.pm:
            print("Closing process...")
            self.pm.close_process()
            self.pm = None
            self.scanned_addresses.clear()
            self.results_list.delete(0, tk.END)
            print("Process closed.")

    def start_scan_memory(self):
        if self.is_scanning:
            return
        if not self.pm:
            self.status_label.configure(text="Please select a process first")
            print("Please select a process first")
            return
        print("Starting memory scan...")
        threading.Thread(target=self.scan_memory, daemon=True).start()

    def scan_memory(self):
        self.is_scanning = True
        self.scan_button.configure(state="disabled")
        try:
            value = self.scan_value_entry.get().strip()
            if not value:
                self.status_label.configure(text="Please enter a value to scan")
                print("Please enter a value to scan")
                return

            search_values = [value.encode('utf-8'), value.encode('utf-16le')]

            self.scanned_addresses.clear()
            self.results_list.delete(0, tk.END)
            self.status_label.configure(text="Scanning...")
            print("Scanning memory...")

            scan_type = self.scan_type_combo.get()

            for module in self.pm.list_modules():
                if not self.is_scanning:
                    break
                try:
                    base = module.lpBaseOfDll
                    size = module.SizeOfImage
                    memory = self.pm.read_bytes(base, size)

                    for search_value in search_values:
                        offset = 0
                        while offset < len(memory) - len(search_value):
                            try:
                                if memory[offset:offset+len(search_value)] == search_value:
                                    addr = base + offset
                                    self.scanned_addresses.append(addr)
                                    self.root.after(0, self.results_list.insert, tk.END, f"{hex(addr)} -> {value}")
                                    print(f"Found value at address: {hex(addr)}")
                                offset += 1
                            except:
                                offset += 1
                                continue
                except PymemError:
                    continue

            self.status_label.configure(text=f"Found {len(self.scanned_addresses)} matches")
            print(f"Found {len(self.scanned_addresses)} matches")
        except Exception as e:
            self.status_label.configure(text=f"Scan error: {e}")
            print(f"Scan error: {e}")
        finally:
            self.is_scanning = False
            self.scan_button.configure(state="normal")
            print("Memory scan completed.")

    def next_scan_memory(self):
        if not self.scanned_addresses:
            self.status_label.configure(text="No previous scan data to refine")
            print("No previous scan data to refine")
            return

        new_value = self.scan_value_entry.get().strip()
        if not new_value:
            self.status_label.configure(text="Please enter a value for next scan")
            print("Please enter a value for next scan")
            return

        try:
            new_value_bytes = new_value.encode('utf-8')
            new_matches = []

            for addr in self.scanned_addresses:
                try:
                    current_value = self.pm.read_bytes(addr, len(new_value_bytes))
                    if current_value == new_value_bytes:
                        new_matches.append(addr)
                except PymemError:
                    continue

            self.scanned_addresses = new_matches
            self.results_list.delete(0, tk.END)
            for addr in self.scanned_addresses:
                self.results_list.insert(tk.END, f"{hex(addr)} -> {new_value}")

            self.status_label.configure(text=f"Refined scan: {len(self.scanned_addresses)} matches")
            print(f"Refined scan: {len(self.scanned_addresses)} matches")
        except Exception as e:
            self.status_label.configure(text=f"Next scan error: {e}")
            print(f"Next scan error: {e}")

    def update_value(self):
        if not self.pm or not self.scanned_addresses:
            self.status_label.configure(text="Nothing to update")
            print("Nothing to update")
            return
        
        new_value = self.new_value_entry.get().strip()
        if not new_value:
            self.status_label.configure(text="Please enter a new value")
            print("Please enter a new value")
            return

        try:
            write_value = new_value.encode('utf-16le')

            success_count = 0
            for addr in self.scanned_addresses:
                try:
                    self.pm.write_bytes(addr, write_value, len(write_value))
                    success_count += 1
                    print(f"Updated value at address: {hex(addr)}")
                except PymemError:
                    continue
                
            self.status_label.configure(text=f"Updated {success_count} addresses")
            print(f"Updated {success_count} addresses")
        except Exception as e:
            self.status_label.configure(text=f"Update error: {e}")
            print(f"Update error: {e}")

    def monitor_memory(self):
        if not self.pm or not self.scanned_addresses:
            return

        self.is_monitoring = True
        while self.is_monitoring:
            for addr in self.scanned_addresses:
                try:
                    value = self.pm.read_bytes(addr, 4) 
                    print(f"Memory at {hex(addr)}: {value}")
                except PymemError:
                    continue

    def stop_monitoring(self):
        self.is_monitoring = False
        self.status_label.configure(text="Monitoring stopped.")


if __name__ == "__main__":
    root = ctk.CTk()
    app = MemScan(root)
    root.mainloop()

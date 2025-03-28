import pymem
import pygetwindow as gw
import win32process
import customtkinter as ctk
import tkinter as tk
import threading
from pymem.exception import PymemError
import struct


class MemScan:
    def __init__(self, root):
        self.root = root
        self.root.title("Memory Scanner")
        self.root.geometry("1000x700")
        self.root.configure(bg="#1e1e2e")
        
        self.pm = None
        self.scanned_addresses = []
        self.is_scanning = False
        self.is_monitoring = False
        
        ctk.set_appearance_mode("dark")
        
        main_frame = ctk.CTkFrame(root)
        main_frame.pack(pady=20, padx=20, fill=tk.BOTH, expand=True)
        
        left_frame = ctk.CTkFrame(main_frame)
        left_frame.pack(side=tk.LEFT, padx=10, pady=10, fill=tk.Y)
        
        self.process_list = tk.Listbox(left_frame, width=50, height=20, font=("Helvetica", 12))
        self.process_list.pack(pady=10)
        
        self.refresh_button = ctk.CTkButton(left_frame, text="Refresh", command=self.refresh_process_list)
        self.refresh_button.pack(pady=10)
        
        right_frame = ctk.CTkFrame(main_frame)
        right_frame.pack(side=tk.RIGHT, padx=10, pady=10, fill=tk.BOTH, expand=True)
        
        self.scan_value_entry = ctk.CTkEntry(right_frame, placeholder_text="Value to scan")
        self.scan_value_entry.pack(pady=10, padx=20, fill=tk.X)
        
        self.scan_type_combo = ctk.CTkComboBox(
            right_frame, values=["Integer", "Float", "String"], state="readonly"
        )
        self.scan_type_combo.set("Integer")
        self.scan_type_combo.pack(pady=10, padx=20, fill=tk.X)
        
        button_frame = ctk.CTkFrame(right_frame)
        button_frame.pack(pady=10)
        
        self.scan_button = ctk.CTkButton(button_frame, text="Scan", command=self.start_scan_memory)
        self.scan_button.pack(side=tk.LEFT, padx=5)
        
        self.next_scan_button = ctk.CTkButton(button_frame, text="Next Scan", command=self.next_scan_memory)
        self.next_scan_button.pack(side=tk.LEFT, padx=5)
        
        self.results_list = tk.Listbox(right_frame, width=50, height=10, font=("Helvetica", 12))
        self.results_list.pack(pady=10, padx=20, fill=tk.BOTH, expand=True)
        
        self.new_value_entry = ctk.CTkEntry(right_frame, placeholder_text="New Value")
        self.new_value_entry.pack(pady=10, padx=20, fill=tk.X)
        
        self.update_button = ctk.CTkButton(right_frame, text="Change Value", command=self.update_value)
        self.update_button.pack(pady=10)
        
        self.status_label = ctk.CTkLabel(right_frame, text="Ready")
        self.status_label.pack(pady=10)

        self.progress_bar = ctk.CTkProgressBar(right_frame)
        self.progress_bar.pack(pady=10, padx=20, fill=tk.X)
        self.progress_bar.set(0)
        
        self.get_process_list()
    
    def get_process_list(self):
        self.process_list.delete(0, tk.END)
        try:
            processes = [(win32process.GetWindowThreadProcessId(win._hWnd)[1], win.title) 
                        for win in gw.getAllWindows() 
                        if win.visible and win.title]
            for pid, title in sorted(processes, key=lambda x: x[1]):
                self.process_list.insert(tk.END, f"{title} (PID: {pid})")
        except Exception as e:
            self.status_label.configure(text=f"Error: {e}")
        self.process_list.bind("<Double-Button-1>", self.select_process)

    def refresh_process_list(self):
        self.close_process()
        self.get_process_list()

    def select_process(self, event):
        if not self.process_list.curselection():
            return
        selected = self.process_list.get(self.process_list.curselection()[0])
        try:
            pid = int(selected.split("(PID: ")[1][:-1])
            self.attach_to_process(pid)
        except (IndexError, ValueError) as e:
            self.status_label.configure(text=f"Error selecting process: {e}")

    def attach_to_process(self, pid):
        self.close_process()
        try:
            self.pm = pymem.Pymem(pid)
            self.status_label.configure(text=f"Attached to PID: {pid}")
            return True
        except PymemError as e:
            self.status_label.configure(text=f"Failed to attach: {e}")
            self.pm = None
            return False

    def close_process(self):
        if self.pm:
            self.pm.close_process()
            self.pm = None
            self.scanned_addresses.clear()
            self.results_list.delete(0, tk.END)

    def start_scan_memory(self):
        if self.is_scanning:
            return
        if not self.pm:
            self.status_label.configure(text="Please select a process first")
            return
        threading.Thread(target=self.scan_memory, daemon=True).start()

    def scan_memory(self):
        print("[DEBUG] Starting memory scan...")
        self.is_scanning = True
        self.scan_button.configure(state="disabled")
        try:
            value = self.scan_value_entry.get().strip()
            print(f"[DEBUG] Value to scan: {value}")
            if not value:
                self.status_label.configure(text="Please enter a value to scan")
                print("[DEBUG] No value entered for scanning.")
                return

            scan_type = self.scan_type_combo.get()
            print(f"[DEBUG] Scan type selected: {scan_type}")
            if scan_type == "Integer":
                try:
                    search_value = int(value).to_bytes(4, byteorder='little', signed=True)
                    print(f"[DEBUG] Integer value converted to bytes: {search_value}")
                except ValueError:
                    self.status_label.configure(text="Invalid integer value")
                    print("[ERROR] Invalid integer value entered.")
                    return
                search_values = [search_value]
            elif scan_type == "Float":
                try:
                    search_value = struct.pack('f', float(value))
                    print(f"[DEBUG] Float value converted to bytes: {search_value}")
                except ValueError:
                    self.status_label.configure(text="Invalid float value")
                    print("[ERROR] Invalid float value entered.")
                    return
                search_values = [search_value]
            elif scan_type == "String":
                search_values = [value.encode('utf-8'), value.encode('utf-16le')]
                print(f"[DEBUG] String value converted to bytes: {search_values}")
            else:
                self.status_label.configure(text="Unsupported scan type")
                print("[ERROR] Unsupported scan type selected.")
                return

            self.scanned_addresses.clear()
            self.results_list.delete(0, tk.END)
            self.status_label.configure(text="Scanning...")
            print("[DEBUG] Cleared previous scan results.")

            total_size = sum(module.SizeOfImage for module in self.pm.list_modules())
            print(f"[DEBUG] Total memory size to scan: {total_size}")
            scanned_size = 0

            for module in self.pm.list_modules():
                if not self.is_scanning:
                    print("[DEBUG] Scan interrupted by user.")
                    break
                try:
                    base = module.lpBaseOfDll
                    size = module.SizeOfImage
                    memory = self.pm.read_bytes(base, size)

                    for search_value in search_values:
                        offset = 0
                        while offset < len(memory) - len(search_value):
                            if memory[offset:offset + len(search_value)] == search_value:
                                addr = base + offset
                                self.scanned_addresses.append(addr)
                                print(f"[DEBUG] Match found at address: {hex(addr)}")
                                self.root.after(0, self.results_list.insert, tk.END, f"{hex(addr)} -> {value}")
                            offset += 1

                    scanned_size += size
                    progress = scanned_size / total_size
                    self.root.after(0, self.progress_bar.set, progress)
                    print(f"[DEBUG] Progress: {progress * 100:.2f}%")
                except PymemError as e:
                    print(f"[ERROR] Error reading module memory: {e}")
                    continue

            self.status_label.configure(text=f"Found {len(self.scanned_addresses)} matches")
            print(f"[DEBUG] Scan complete. Matches found: {len(self.scanned_addresses)}")
        except Exception as e:
            self.status_label.configure(text=f"Scan error: {e}")
            print(f"[ERROR] Scan error: {e}")
        finally:
            self.is_scanning = False
            self.scan_button.configure(state="normal")
            self.root.after(0, self.progress_bar.set, 0)
            print("[DEBUG] Scan finished. UI reset.")

    def next_scan_memory(self):
        if not self.scanned_addresses:
            self.status_label.configure(text="No previous scan data to refine")
            return

        new_value = self.scan_value_entry.get().strip()
        if not new_value:
            self.status_label.configure(text="Please enter a value for next scan")
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
        except Exception as e:
            self.status_label.configure(text=f"Next scan error: {e}")

    def update_value(self):
        print("[DEBUG] Starting value update...")
        if not self.pm or not self.scanned_addresses:
            self.status_label.configure(text="Nothing to update")
            print("[DEBUG] No process attached or no scanned addresses.")
            return

        new_value = self.new_value_entry.get().strip()
        print(f"[DEBUG] New value to write: {new_value}")
        if not new_value:
            self.status_label.configure(text="Please enter a new value")
            print("[DEBUG] No new value entered.")
            return

        scan_type = self.scan_type_combo.get()
        print(f"[DEBUG] Scan type for update: {scan_type}")
        try:
            if scan_type == "Integer":
                try:
                    write_value = int(new_value).to_bytes(4, byteorder='little', signed=True)
                    print(f"[DEBUG] Integer value converted to bytes: {write_value}")
                except ValueError:
                    self.status_label.configure(text="Invalid integer value")
                    print("[ERROR] Invalid integer value entered.")
                    return
            elif scan_type == "Float":
                try:
                    write_value = struct.pack('f', float(new_value))
                    print(f"[DEBUG] Float value converted to bytes: {write_value}")
                except ValueError:
                    self.status_label.configure(text="Invalid float value")
                    print("[ERROR] Invalid float value entered.")
                    return
            elif scan_type == "String":
                write_value = new_value.encode('utf-8')
                print(f"[DEBUG] String value converted to bytes: {write_value}")
            else:
                self.status_label.configure(text="Unsupported data type")
                print("[ERROR] Unsupported data type selected.")
                return

            success_count = 0
            for addr in self.scanned_addresses:
                try:
                    self.pm.write_bytes(addr, write_value, len(write_value))
                    success_count += 1
                    print(f"[DEBUG] Successfully wrote to address: {hex(addr)}")
                except PymemError as e:
                    print(f"[ERROR] Failed to write to address {hex(addr)}: {e}")
                    continue

            self.status_label.configure(text=f"Updated {success_count} addresses")
            print(f"[DEBUG] Successfully updated {success_count} addresses.")
        except Exception as e:
            print(f"[ERROR] Update error: {e}")
            self.status_label.configure(text=f"Update error: {e}")


if __name__ == "__main__":
    root = ctk.CTk()
    app = MemScan(root)
    root.mainloop()

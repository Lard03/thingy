import pymem
import pygetwindow as gw
import win32process
import customtkinter as ctk
import tkinter as tk
import threading
from pymem.exception import PymemError
import struct
import time


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
        
        self.pointer_scan_button = ctk.CTkButton(button_frame, text="Pointer Scan", command=lambda: self.find_pointer_to(self.scan_value_entry.get()))
        self.pointer_scan_button.pack(side=tk.LEFT, padx=5)
        
        self.results_list = tk.Listbox(right_frame, width=50, height=10, font=("Helvetica", 12))
        self.results_list.pack(pady=10, padx=20, fill=tk.BOTH, expand=True)
        
        self.new_value_entry = ctk.CTkEntry(right_frame, placeholder_text="New Value")
        self.new_value_entry.pack(pady=10, padx=20, fill=tk.X)
        
        self.update_button = ctk.CTkButton(right_frame, text="Change Value", command=self.update_value)
        self.update_button.pack(pady=10)
        
        self.freeze_button = ctk.CTkButton(right_frame, text="Freeze Value", command=self.toggle_freeze)
        self.freeze_button.pack(pady=10)
        
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
        self.is_scanning = True
        self.scan_button.configure(state="disabled")
        try:
            value = self.scan_value_entry.get().strip()
            if not value:
                self.status_label.configure(text="Please enter a value to scan")
                return

            scan_type = self.scan_type_combo.get()
            if scan_type == "Integer":
                try:
                    search_value = int(value).to_bytes(4, byteorder='little', signed=True)
                except ValueError:
                    self.status_label.configure(text="Invalid integer value")
                    return
                search_values = [search_value]
            elif scan_type == "Float":
                try:
                    search_value = struct.pack('f', float(value))
                except ValueError:
                    self.status_label.configure(text="Invalid float value")
                    return
                search_values = [search_value]
            elif scan_type == "String":
                search_values = [value.encode('utf-8'), value.encode('utf-16le')]
            else:
                self.status_label.configure(text="Unsupported scan type")
                return

            self.scanned_addresses.clear()
            self.results_list.delete(0, tk.END)
            self.status_label.configure(text="Scanning...")

            chunk_size = 1024 * 1024
            memory_regions = self.get_valid_memory_regions()
            total_size = sum(region[1] for region in memory_regions)
            scanned_size = 0

            for base, size in memory_regions:
                if not self.is_scanning:
                    break
                try:
                    for offset in range(0, size, chunk_size):
                        if not self.is_scanning:
                            break
                        chunk = self.pm.read_bytes(base + offset, min(chunk_size, size - offset))

                        for search_value in search_values:
                            chunk_offset = 0
                            while chunk_offset < len(chunk) - len(search_value):
                                if chunk[chunk_offset:chunk_offset + len(search_value)] == search_value:
                                    addr = base + offset + chunk_offset
                                    self.scanned_addresses.append(addr)
                                    self.root.after(0, self.results_list.insert, tk.END, f"{hex(addr)} -> {value}")
                                chunk_offset += max(1, len(search_value))

                        scanned_size += min(chunk_size, size - offset)
                        progress = scanned_size / total_size
                        self.root.after(0, self.progress_bar.set, progress)
                except PymemError:
                    continue

            self.status_label.configure(text=f"Found {len(self.scanned_addresses)} matches")
        except Exception as e:
            self.status_label.configure(text=f"Scan error: {e}")
        finally:
            self.is_scanning = False
            self.scan_button.configure(state="normal")
            self.root.after(0, self.progress_bar.set, 0)  # Reset progress bar

    def get_valid_memory_regions(self):
        regions = []
        process_handle = self.pm.process_handle
        address = 0
        while address < 0x7FFFFFFF:
            mbi = pymem.ressources.structure.MEMORY_BASIC_INFORMATION()
            result = pymem.memory.virtual_query(process_handle, address)
            if result:
                mbi = result
                if mbi.State == 0x1000 and mbi.Protect in (0x04, 0x02, 0x20, 0x40):
                    regions.append((mbi.BaseAddress, mbi.RegionSize))
                address += mbi.RegionSize
            else:
                address += 0x1000
        return regions

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
        if not self.pm or not self.scanned_addresses:
            self.status_label.configure(text="Nothing to update")
            return
        
        new_value = self.new_value_entry.get().strip()
        if not new_value:
            self.status_label.configure(text="Please enter a new value")
            return

        try:
            write_value = new_value.encode('utf-16le')

            success_count = 0
            for addr in self.scanned_addresses:
                try:
                    self.pm.write_bytes(addr, write_value, len(write_value))
                    success_count += 1
                except PymemError:
                    continue
                
            self.status_label.configure(text=f"Updated {success_count} addresses")
        except Exception as e:
            self.status_label.configure(text=f"Update error: {e}")

    def find_pointer_to(self, target_address):
        if not self.pm:
            self.status_label.configure(text="Please attach to a process first")
            return

        try:
            target_address = int(target_address, 16)
        except ValueError:
            self.status_label.configure(text="Invalid target address")
            return

        self.results_list.delete(0, tk.END)
        self.status_label.configure(text="Scanning for pointers...")
        regions = self.get_valid_memory_regions()

        for base, size in regions:
            try:
                chunk = self.pm.read_bytes(base, size)
                for i in range(0, size - 4, 4):
                    val = struct.unpack("I", chunk[i:i + 4])[0]
                    if val == target_address:
                        self.results_list.insert(tk.END, f"Pointer -> {hex(base + i)}")
            except PymemError:
                continue

        self.status_label.configure(text="Pointer scan complete")

    def freeze_value(self, address, value_bytes):
        def freeze_loop():
            while self.is_monitoring:
                try:
                    self.pm.write_bytes(address, value_bytes, len(value_bytes))
                except:
                    break
                time.sleep(0.1)
        self.is_monitoring = True
        threading.Thread(target=freeze_loop, daemon=True).start()

    def toggle_freeze(self):
        if not self.pm or not self.scanned_addresses:
            self.status_label.configure(text="No value selected to freeze")
            return

        if self.is_monitoring:
            self.is_monitoring = False
            self.status_label.configure(text="Freezing stopped")
        else:
            selected = self.results_list.curselection()
            if not selected:
                self.status_label.configure(text="Please select a value to freeze")
                return

            try:
                selected_address = self.scanned_addresses[selected[0]]
                value = self.new_value_entry.get().strip()
                if not value:
                    self.status_label.configure(text="Please enter a value to freeze")
                    return

                value_bytes = value.encode('utf-16le')  # Adjust encoding as needed
                self.freeze_value(selected_address, value_bytes)
                self.status_label.configure(text=f"Freezing value at {hex(selected_address)}")
            except Exception as e:
                self.status_label.configure(text=f"Freeze error: {e}")


if __name__ == "__main__":
    root = ctk.CTk()
    app = MemScan(root)
    root.mainloop()

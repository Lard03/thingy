import pymem
import pygetwindow as gw
import win32process
import threading
import time
import regex as re
from pymem.exception import PymemError
from util.typeconversion import convert_to_bytes, Type
from util.memstructures import Address, Region
from util.memregions import init_process, process


class MemoryScanner:
    def __init__(self, update_status_callback, update_results_callback, update_progress_callback):
        self.pm = None
        self.scanned_addresses = []
        self.is_scanning = False
        self.is_monitoring = False
        self.monitor_thread = None
        self.frozen_indices = set()
        self.update_status = update_status_callback
        self.update_results = update_results_callback
        self.update_progress = update_progress_callback

    def get_process_list(self):
        try:
            processes = [(win32process.GetWindowThreadProcessId(win._hWnd)[1], win.title)
                         for win in gw.getAllWindows()
                         if win.visible and win.title]
            return sorted(processes, key=lambda x: x[1])
        except Exception as e:
            self.update_status(f"Error: {e}")
            return []

    def attach_to_process(self, pid):
        self.close_process()
        try:
            self.pm = pymem.Pymem(pid)
            self.update_status(f"Attached to PID: {pid}")
        except PymemError as e:
            self.update_status(f"Failed to attach: {e}")
            self.pm = None

    def close_process(self):
        if self.pm:
            self.pm.close_process()
            self.pm = None
        self.scanned_addresses.clear()
        self.frozen_indices.clear()
        self.update_results([])

    def start_scan_memory(self, value, value_type: Type):
        if self.is_scanning or not self.pm:
            self.update_status("Please select a process first")
            return
        threading.Thread(target=self.scan_memory, args=(value, value_type), daemon=True).start()

    def scan_memory(self, value, value_type: Type):
        self.is_scanning = True
        try:
            search_value = convert_to_bytes(value, value_type)
            if not search_value:
                self.update_status("Unsupported value type")
                return

            self.scanned_addresses.clear()
            self.frozen_indices.clear()
            self.update_results([])
            self.update_status("Scanning...")

            total_size = sum(region.size for region in process(self.pm.process_handle))
            scanned_size = 0
            pattern = re.escape(search_value, special_only=True)
            matches = []

            for region in process(self.pm.process_handle):
                if not self.is_scanning:
                    break
                try:
                    data = self.pm.read_bytes(region.start, region.size)

                    for match in re.finditer(pattern, data, re.DOTALL):
                        addr = region.start + match.start()
                        addr_obj = Address(addr, search_value)
                        matches.append(addr_obj)

                    scanned_size += region.size
                    progress = scanned_size / total_size
                    self.update_progress(progress)

                except PymemError:
                    continue

            self.scanned_addresses = sorted(matches, key=lambda a: a.address)
            result_strings = [f"{hex(addr_obj.address)} -> {value}" for addr_obj in self.scanned_addresses]
            self.update_results(result_strings)
            self.update_status(f"Found {len(self.scanned_addresses)} matches")

        except Exception as e:
            self.update_status(f"Scan error: {e}")
        finally:
            self.is_scanning = False
            self.update_progress(0)

    def get_valid_memory_regions(self):
        process_handle = self.pm.process_handle
        memory_regions, _ = init_process(process_handle)
        return memory_regions

    def next_scan_memory(self, value, value_type: Type):
        if not self.scanned_addresses:
            self.update_status("No previous scan data to refine")
            return

        try:
            new_matches = []
            encoded_new_value = convert_to_bytes(value, value_type)
            for addr_obj in self.scanned_addresses:
                try:
                    current_value = self.pm.read_bytes(addr_obj.address, len(addr_obj.value))
                    if current_value == encoded_new_value:
                        new_matches.append(addr_obj)
                except PymemError:
                    continue

            self.scanned_addresses = new_matches
            result_strings = [f"{hex(addr_obj.address)} -> {value}" for addr_obj in self.scanned_addresses]
            self.update_results(result_strings)
            self.update_status(f"Refined scan: {len(self.scanned_addresses)} total matches")
        except Exception as e:
            self.update_status(f"Next scan error: {e}")

    def freeze_address(self, index):
        if 0 <= index < len(self.scanned_addresses):
            self.frozen_indices.add(index)
            self.update_status(f"Address {hex(self.scanned_addresses[index].address)} frozen")
        else:
            self.update_status("Invalid index for freezing.")

    def unfreeze_address(self, index):
        if index in self.frozen_indices:
            self.frozen_indices.remove(index)
            self.update_status(f"Address {hex(self.scanned_addresses[index].address)} unfrozen")
        else:
            self.update_status("Address not frozen or invalid index.")

    def edit_address(self, index, new_value_str, value_type: Type):
        if 0 <= index < len(self.scanned_addresses):
            addr_obj = self.scanned_addresses[index]
            try:
                encoded_value = convert_to_bytes(new_value_str, value_type)
                self.pm.write_bytes(addr_obj.address, encoded_value, len(encoded_value))
                addr_obj.value = encoded_value
                self.update_status(f"Address {hex(addr_obj.address)} updated to {new_value_str}")
            except PymemError as e:
                self.update_status(f"Error updating address: {e}")
        else:
            self.update_status("Invalid index for editing.")

    def delete_address(self, index):
        if 0 <= index < len(self.scanned_addresses):
            if index in self.frozen_indices:
                self.frozen_indices.remove(index)
            del self.scanned_addresses[index]
            self.frozen_indices = {i if i < index else i - 1 for i in self.frozen_indices if i != index}
            self.update_status("Address deleted")
            self.update_results([f"{hex(addr_obj.address)} -> {addr_obj.value}" for addr_obj in self.scanned_addresses])
        else:
            self.update_status("Invalid index for deletion.")

    def start_monitoring(self):
        if not self.pm:
            self.update_status("No process attached")
            return
        if self.is_monitoring:
            self.update_status("Already monitoring addresses")
            return
        self.is_monitoring = True
        self.monitor_thread = threading.Thread(target=self.monitor_addresses, daemon=True)
        self.monitor_thread.start()
        self.update_status("Started monitoring addresses")

    def stop_monitoring(self):
        self.is_monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join()
            self.monitor_thread = None
        self.update_status("Stopped monitoring addresses")

    def monitor_addresses(self):
        while self.is_monitoring:
            results = []
            for idx, addr_obj in enumerate(self.scanned_addresses):
                try:
                    if idx in self.frozen_indices:

                        self.pm.write_bytes(addr_obj.address, addr_obj.value, len(addr_obj.value))
                    else:
                        new_value = self.pm.read_bytes(addr_obj.address, len(addr_obj.value))
                        addr_obj.value = new_value
                    results.append(f"{hex(addr_obj.address)} -> {addr_obj.value}")
                except PymemError:
                    continue
            self.update_results(results)
            time.sleep(0.5)


import customtkinter as ctk
import tkinter as tk
from scanner.scan import MemoryScanner
from util.typeconversion import Type


class MemScanUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Memory Scanner")
        self.root.geometry("1000x700")
        self.root.configure(bg="#1e1e2e")

        self.scanner = MemoryScanner(self.update_status, self.update_results, self.update_progress)

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

        self.value_type_var = ctk.StringVar(value=Type.Int32.value)
        self.value_type_dropdown = ctk.CTkOptionMenu(
            right_frame,
            variable=self.value_type_var,
            values=[t.value for t in Type]
        )
        self.value_type_dropdown.pack(pady=10)

        button_frame = ctk.CTkFrame(right_frame)
        button_frame.pack(pady=10)

        self.scan_button = ctk.CTkButton(button_frame, text="Scan", command=self.start_scan_memory)
        self.scan_button.pack(side=tk.LEFT, padx=5)

        self.next_scan_button = ctk.CTkButton(button_frame, text="Next Scan", command=self.next_scan_memory)
        self.next_scan_button.pack(side=tk.LEFT, padx=5)

        self.pointer_scan_button = ctk.CTkButton(button_frame, text="Pointer Scan", command=self.pointer_scan)
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

        self.refresh_process_list()

    def refresh_process_list(self):
        self.scanner.close_process()
        self.process_list.delete(0, tk.END)
        processes = self.scanner.get_process_list()
        for pid, title in processes:
            self.process_list.insert(tk.END, f"{title} (PID: {pid})")
        self.process_list.bind("<Double-Button-1>", self.select_process)

    def select_process(self, event):
        if not self.process_list.curselection():
            return
        selected = self.process_list.get(self.process_list.curselection()[0])
        pid = int(selected.split("(PID: ")[1][:-1])
        self.scanner.attach_to_process(pid)

    def start_scan_memory(self):
        value = self.scan_value_entry.get().strip()
        value_type = Type(self.value_type_var.get())
        self.scanner.start_scan_memory(value, value_type)

    def next_scan_memory(self):
        value = self.scan_value_entry.get().strip()
        self.scanner.next_scan_memory(value)

    def pointer_scan(self):
        target_address = self.scan_value_entry.get().strip()
        self.scanner.find_pointer_to(target_address)

    def update_value(self):
        new_value = self.new_value_entry.get().strip()
        self.scanner.update_value(new_value)

    def toggle_freeze(self):
        selected = self.results_list.curselection()
        if not selected:
            self.update_status("Please select a value to freeze")
            return
        index = selected[0]
        self.scanner.toggle_freeze(index)

    def update_status(self, message):
        self.status_label.configure(text=message)

    def update_results(self, results):

        for result in results:
            self.results_list.insert(tk.END, result)

    def update_progress(self, progress):
        self.progress_bar.set(progress)


if __name__ == "__main__":
    root = ctk.CTk()
    app = MemScanUI(root)
    root.mainloop()
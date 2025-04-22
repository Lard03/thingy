import customtkinter as ctk
import tkinter as tk
from tkinter import Scrollbar
from scan import MemoryScanner
from util.typeconversion import Type


class MemScanUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Memory Scanner")
        self.root.geometry("1000x700")
        self.root.configure(bg="#1e1e2e")

        ctk.set_appearance_mode("dark")
        self.current_mode = "dark"

        def safe_callback(func):
            return lambda *args, **kwargs: self.root.after(0, func, *args, **kwargs)

        self.scanner = MemoryScanner(
            safe_callback(self.update_status),
            safe_callback(self.update_results),
            safe_callback(self.update_progress)
        )

        self.mode_menu = tk.Menu(self.root, tearoff=0)
        self.mode_menu.add_command(label="Toggle Light/Dark Mode", command=self.toggle_mode)

        self.root.bind("<Button-3>", self.show_mode_menu)

        main_frame = ctk.CTkFrame(self.root)
        main_frame.pack(padx=20, pady=20, fill=tk.BOTH, expand=True)

        process_frame = ctk.CTkFrame(main_frame)
        process_frame.pack(side=tk.LEFT, fill=tk.Y, padx=10)

        ctk.CTkLabel(process_frame, text="Running Processes").pack(pady=5)
        self.process_list = tk.Listbox(process_frame, width=40, height=20, font=("Helvetica", 12))
        self.process_list.pack(pady=5)
        self.process_list.bind("<Double-Button-1>", self.select_process)

        self.refresh_button = ctk.CTkButton(process_frame, text="Refresh", command=self.refresh_process_list)
        self.refresh_button.pack(pady=5)

        control_frame = ctk.CTkFrame(main_frame)
        control_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=10)

        input_frame = ctk.CTkFrame(control_frame)
        input_frame.pack(pady=10, padx=20, fill=tk.X)

        self.scan_value_entry = ctk.CTkEntry(input_frame, placeholder_text="Value to scan")
        self.scan_value_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))

        self.value_type_var = tk.StringVar(value=Type.Int32.value)
        self.value_type_dropdown = ctk.CTkOptionMenu(
            input_frame, variable=self.value_type_var,
            values=[t.value for t in Type],
            width=100
        )
        self.value_type_dropdown.pack(side=tk.RIGHT)

        button_frame = ctk.CTkFrame(control_frame)
        button_frame.pack(pady=5)

        self.scan_button = ctk.CTkButton(button_frame, text="Scan", command=self.start_scan_memory)
        self.scan_button.pack(side=tk.LEFT, padx=5)

        self.next_scan_button = ctk.CTkButton(button_frame, text="Next Scan", command=self.next_scan_memory)
        self.next_scan_button.pack(side=tk.LEFT, padx=5)

        ctk.CTkLabel(control_frame, text="Scan Results").pack(pady=5)
        results_frame = ctk.CTkFrame(control_frame)
        results_frame.pack(pady=5, padx=20, fill=tk.BOTH, expand=True)

        self.results_list = tk.Listbox(results_frame, font=("Helvetica", 12), selectmode=tk.SINGLE)
        self.results_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scrollbar = Scrollbar(results_frame, command=self.results_list.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.results_list.config(yscrollcommand=scrollbar.set)

        self.context_menu = tk.Menu(self.results_list, tearoff=0)
        self.context_menu.add_command(label="Freeze/Unfreeze", command=self.toggle_freeze_from_context)

        self.results_list.bind("<Button-3>", self.show_context_menu)

        new_value_frame = ctk.CTkFrame(control_frame)
        new_value_frame.pack(pady=10, padx=20, fill=tk.X)

        self.new_value_entry = ctk.CTkEntry(new_value_frame, placeholder_text="New Value")
        self.new_value_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))

        self.update_button = ctk.CTkButton(new_value_frame, text="Change Value", command=self.update_value)
        self.update_button.pack(side=tk.RIGHT)

        self.status_label = ctk.CTkLabel(control_frame, text="Ready")
        self.status_label.pack(pady=10)

        self.progress_bar = ctk.CTkProgressBar(control_frame)
        self.progress_bar.pack(pady=5, padx=20, fill=tk.X)
        self.progress_bar.set(0)

        self.refresh_process_list()

    def refresh_process_list(self):
        self.scanner.close_process()
        self.process_list.delete(0, tk.END)
        for pid, title in self.scanner.get_process_list():
            self.process_list.insert(tk.END, f"{title} (PID: {pid})")

    def select_process(self, event):
        if not self.process_list.curselection():
            return
        selected = self.process_list.get(self.process_list.curselection()[0])
        pid = int(selected.split("(PID: ")[1][:-1])
        self.scanner.attach_to_process(pid)
        self.scan_value_entry.delete(0, tk.END)
        self.update_status("Attached to process. Ready to scan.")

    def start_scan_memory(self):
        value = self.scan_value_entry.get().strip()
        if not value:
            self.update_status("Please enter a value to scan")
            return
        value_type = Type(self.value_type_var.get())
        self.scanner.start_scan_memory(value, value_type)

    def next_scan_memory(self):
        value = self.scan_value_entry.get().strip()
        if not value:
            self.update_status("Please enter a value to refine scan")
            return
        value_type = Type(self.value_type_var.get())
        self.scanner.next_scan_memory(value, value_type)

    def update_value(self):
        new_value = self.new_value_entry.get().strip()
        selected = self.results_list.curselection()
        if not selected:
            self.update_status("Please select a value to update")
            return

        index = selected[0]
        value_type = Type(self.value_type_var.get())
        self.scanner.edit_address(index, new_value, value_type)
        current_item = self.results_list.get(index)
        address = current_item.split(" -> ")[0]

        if "[Frozen]" in current_item:
            updated_item = f"{address} -> [Frozen] {new_value}"
        else:
            updated_item = f"{address} -> {new_value}"

        self.results_list.delete(index)
        self.results_list.insert(index, updated_item)
        self.results_list.itemconfig(index, {'fg': 'green'})
        self.new_value_entry.delete(0, tk.END)
        self.update_status("Value updated successfully")

    def toggle_freeze(self):
        selected = self.results_list.curselection()
        if not selected:
            self.update_status("Please select a value to freeze/unfreeze")
            return
        index = selected[0]
        if index in self.scanner.frozen_indices:
            self.scanner.unfreeze_address(index)
            self.tag_unfreeze(index)
        else:
            self.scanner.freeze_address(index)
            self.tag_freeze(index)

    def show_context_menu(self, event):
        try:
            self.context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.context_menu.grab_release()

    def toggle_freeze_from_context(self):
        selected = self.results_list.curselection()
        if not selected:
            self.update_status("Please select a value to freeze/unfreeze")
            return
        index = selected[0]
        if index in self.scanner.frozen_indices:
            self.scanner.unfreeze_address(index)
            self.tag_unfreeze(index)
        else:
            self.scanner.freeze_address(index)
            self.tag_freeze(index)

    def tag_freeze(self, index):
        value = self.results_list.get(index)
        self.results_list.delete(index)
        self.results_list.insert(index, f"[Frozen] {value}")
        self.results_list.itemconfig(index, {'fg': 'blue'})

    def tag_unfreeze(self, index):
        value = self.results_list.get(index).replace("[Frozen] ", "")
        self.results_list.delete(index)
        self.results_list.insert(index, value)
        self.results_list.itemconfig(index, {'fg': 'black'})

    def update_status(self, message):
        self.status_label.configure(text=message)

    def update_results(self, results):
        yview = self.results_list.yview()
        self.results_list.delete(0, tk.END)
        for i, result in enumerate(results):
            if i in self.scanner.frozen_indices:
                self.results_list.insert(tk.END, f"[Frozen] {result}")
                self.results_list.itemconfig(tk.END, {'fg': 'blue'})
            else:
                self.results_list.insert(tk.END, result)
        self.results_list.yview_moveto(yview[0])

    def update_progress(self, progress):
        self.progress_bar.set(progress)

    def show_mode_menu(self, event):
        try:
            self.mode_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.mode_menu.grab_release()

    def toggle_mode(self):
        if self.current_mode == "dark":
            ctk.set_appearance_mode("light")
            self.current_mode = "light"
        else:
            ctk.set_appearance_mode("dark")
            self.current_mode = "dark"


if __name__ == "__main__":
    root = ctk.CTk()
    app = MemScanUI(root)
    root.mainloop()
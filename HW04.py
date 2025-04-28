import os
import tempfile
import shutil
import tkinter as tk
from tkinter import messagebox, scrolledtext, filedialog, Toplevel, Text
import yara
from datetime import datetime

# Initial YARA rule text
YARA_RULE = '''
rule DetectSuspiciousPatterns {
    meta:
        description = "Detects common suspicious commands and indicators"

    strings:
        $a = "powershell"
        $b = "curl"
        $c = "cmd.exe"
        $d = "wget"
        $e = "base64"
        $f = "net user"
        $g = "/wp-admin"
        $h = "/phpmyadmin"
        $i = ".env"
        $j = "' OR '1'='1" nocase
        $k = "--"
        $l = "&&"
        $m = "||"
        $n = "$("

    condition:
        any of them
}
'''
# Preserve default for reset
DEFAULT_YARA_RULE = YARA_RULE

# Function to compile YARA rules from text
def compile_rules(rule_text):
    with tempfile.NamedTemporaryFile(suffix=".yar", delete=False, mode='w') as f:
        f.write(rule_text)
        path = f.name
    try:
        return yara.compile(filepath=path)
    except yara.SyntaxError as e:
        messagebox.showerror("YARA Syntax Error", str(e))
        return None

# Compile initial rules
rules = compile_rules(YARA_RULE)

# Identifier lookup for match descriptions
identifier_lookup = {
    "$a": "powershell",
    "$b": "curl",
    "$c": "cmd.exe",
    "$d": "wget",
    "$e": "base64",
    "$f": "net user",
    "$g": "/wp-admin",
    "$h": "/phpmyadmin",
    "$i": ".env",
    "$j": "SQL Injection attempt",
    "$k": "-- (SQL comment)",
    "$l": "command injection: &&",
    "$m": "command injection: ||",
    "$n": "command injection: $("
}

# Scan folder for .txt files
def scan_folder(folder_path):
    findings = []
    if not rules:
        return []
    for root, _, files in os.walk(folder_path):
        for file in files:
            if file.lower().endswith(".txt"):
                file_path = os.path.join(root, file)
                try:
                    matches = rules.match(filepath=file_path)
                    if matches:
                        details = []
                        for m in matches:
                            for s in m.strings:
                                details.append(f"{s.identifier} → {identifier_lookup.get(s.identifier, 'unknown')}")
                        findings.append((file_path, details))
                except Exception as e:
                    findings.append((file_path, [f"Error: {e}"]))
    return findings

class YaraScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("YARA Folder Scanner (.txt files only)")
        # Dark theme background
        self.root.configure(bg="#2e2e2e")

        # Instructions
        tk.Label(root, text="Select a folder to scan all .txt files using YARA", font=("Arial",12,"bold"), bg="#2e2e2e", fg="white").pack(pady=10)

        # Controls frame: all buttons on one line
        controls = tk.Frame(root, bg="#2e2e2e")
        controls.pack(pady=5)

         # Controls frame: all buttons on one line
        controls = tk.Frame(root, bg="#2e2e2e")
        controls.pack(pady=5)

        # Select Folder
        btn_select = tk.Button(controls, text="Select Folder", command=self.select_folder, bg="blue", fg="white")
        btn_select.grid(row=0, column=0, padx=5)
        # Start Scan
        btn_scan = tk.Button(controls, text="Start Scan", command=self.start_scan, bg="#8b0000", fg="white")
        btn_scan.grid(row=0, column=1, padx=5)
        # Export Findings
        btn_export = tk.Button(controls, text="Export Findings", command=self.export_findings, bg="#4a4a4a", fg="white")
        btn_export.grid(row=0, column=2, padx=5)
        # Edit YARA Rules
        btn_edit = tk.Button(controls, text="Edit YARA Rules", command=self.open_rule_editor, bg="#006400", fg="white")
        btn_edit.grid(row=0, column=3, padx=5)
        # Reset Rules
        btn_reset = tk.Button(controls, text="Reset Rules", command=self.reset_rules, bg="#ffc107", fg="black")
        btn_reset.grid(row=0, column=4, padx=5)
        # Identifiers
        btn_id = tk.Button(controls, text="Identifiers", command=self.show_identifiers, bg="#4a4a4a", fg="white")
        btn_id.grid(row=0, column=5, padx=5)
        # Quarantine checkbox centered on its own line
        self.quarantine_var = tk.BooleanVar()
        chk = tk.Checkbutton(root, text="Quarantine corrupted files", variable=self.quarantine_var, bg="#2e2e2e", fg="white", selectcolor="#2e2e2e")
        chk.pack(pady=5)

        # Output area
        self.output = scrolledtext.ScrolledText(root, height=25, width=110, state='disabled', font=("Courier",10), bg="#1e1e1e", fg="white", insertbackground="white")
        self.output.pack(padx=10, pady=10)
        self.folder_path = None
        self.results = []
        self.last_scan_message = ''

    def select_folder(self):
        self.folder_path = filedialog.askdirectory()
        if self.folder_path:
            self._append_output(f"Selected folder: {self.folder_path}\n")

    def start_scan(self):
        if not self.folder_path:
            messagebox.showwarning("No Folder","Please select a folder first.")
            return
        self.output.configure(state='normal')
        self.output.delete('1.0', tk.END)
        self.output.insert(tk.END, f"Scanning folder: {self.folder_path}\n\n")
        self.results = scan_folder(self.folder_path)
        if not self.results:
            self.output.insert(tk.END,"No matches found.\n")
        else:
            for path, details in self.results:
                if self.quarantine_var.get():
                    corrupted_dir = os.path.join(self.folder_path, "corrupted")
                    os.makedirs(corrupted_dir, exist_ok=True)
                    try:
                        shutil.move(path, os.path.join(corrupted_dir, os.path.basename(path)))
                        path = os.path.join(corrupted_dir, os.path.basename(path))
                    except Exception as move_e:
                        messagebox.showerror("Quarantine Error", f"Failed to quarantine {path}: {move_e}")
                self.output.insert(tk.END,f"File: {path}\n")
                for d in details:
                    self.output.insert(tk.END,f"  {d}\n")
                self.output.insert(tk.END,"-"*60+"\n")
        self.output.configure(state='disabled')
        self.last_scan_message = 'Scanning completed.'
        messagebox.showinfo("Scan Complete",self.last_scan_message)

    #   Pop out for the codes
    def show_identifiers(self):
        win = Toplevel(self.root)
        win.title("Identifier Lookup")
        win.configure(bg="#2e2e2e")
        text = scrolledtext.ScrolledText(win, height=12, width=50, bg="#1e1e1e", fg="white", insertbackground="white")
        for key, val in identifier_lookup.items():
            text.insert(tk.END, f"{key} → {val}\n")
        text.configure(state='disabled')
        text.pack(padx=10, pady=10)

    def export_findings(self):
        if not self.results:
            messagebox.showwarning("No Findings","Please run a scan before exporting findings.")
            return
        folder = filedialog.askdirectory(title="Select Folder to Save Findings")
        if not folder:
            return
        report_file = os.path.join(folder,f"scan_findings_{int(datetime.now().timestamp())}.txt")
        try:
            with open(report_file,'w',encoding='utf-8') as f:
                content = self.output.get('1.0', tk.END)
                f.write(content)
                f.write(f"Message: {self.last_scan_message}\n")
            messagebox.showinfo("Exported",f"Findings exported to:\n{report_file}")
        except Exception as e:
            messagebox.showerror("Error",f"Failed to export findings: {e}")

    def open_rule_editor(self):
        editor = Toplevel(self.root)
        editor.title("YARA Rule Editor")
        editor.configure(bg="#2e2e2e")
        text_area = Text(editor,wrap='none', bg="#1e1e1e", fg="white", insertbackground="white")
        text_area.insert(tk.END,YARA_RULE)
        text_area.pack(expand=True,fill='both')
        def save_rules():
            global rules, YARA_RULE
            new_text = text_area.get('1.0',tk.END)
            new_rules = compile_rules(new_text)
            if new_rules:
                rules = new_rules
                YARA_RULE = new_text
                messagebox.showinfo("Success","YARA rules updated successfully.")
                editor.destroy()
        tk.Button(editor,text="Save & Recompile",command=save_rules,bg="#ffd700", fg="black").pack(pady=5)

    #   Revert to default rules
    def reset_rules(self):
        global rules, YARA_RULE
        YARA_RULE = DEFAULT_YARA_RULE
        new_rules = compile_rules(DEFAULT_YARA_RULE)
        if new_rules:
            rules = new_rules
            messagebox.showinfo("Reset","YARA rules have been reset to defaults.")

    def _append_output(self, text):
        self.output.configure(state='normal')
        self.output.insert(tk.END, text)
        self.output.configure(state='disabled')

if __name__ == "__main__":
    root = tk.Tk()
    app = YaraScannerApp(root)
    root.mainloop()

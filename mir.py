import os
import tkinter as tk
from tkinter import filedialog, ttk, messagebox
import datetime
import csv
import openai
import win32evtlog
import winshell
import pythoncom
import win32com.client
import subprocess
from fpdf import FPDF
import sys
import os

# ✅ Use environment variable for security instead of hardcoding API key
openai.api_key = os.getenv("insert-your-key ")

# Suspicious keywords
suspicious_keywords = ['hack', 'kill', 'drugs', 'bitcoin', 'darkweb', 'password', 'admin']
image_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.bmp']
scan_results = []

# Global counter for GPT analysis
gpt_analysis_count = 0
GPT_ANALYSIS_LIMIT = 5  # Set max number of files to analyze with GPT

def is_suspicious_name(filename):
    return any(keyword in filename.lower() for keyword in suspicious_keywords)


def is_suspicious_content(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            return any(keyword in f.read().lower() for keyword in suspicious_keywords)
    except:
        return False



def analyze_image_with_gpt(file_name, created, modified, size):
    global gpt_analysis_count

    # ✅ Check if limit reached
    if gpt_analysis_count >= GPT_ANALYSIS_LIMIT:
        return "Skipped (Limit Reached)"

    prompt = (
        f"This is a digital forensic analysis.\n"
        f"File Name: {file_name}\n"
        f"Created: {created}\n"
        f"Modified: {modified}\n"
        f"Size: {size} bytes\n"
        f"Based on the file name and metadata, is there any indication this image could be suspicious? "
        f"Answer 'Suspicious' or 'Normal' and give a short reason."
    )

    try:
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a digital forensic expert."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=100,
            temperature=0.3
        )

        gpt_analysis_count += 1  # ✅ Increment counter after successful call
        return response.choices[0].message.content.strip()

    except Exception as e:
        print("GPT Error:", e)
        return "GPT Analysis Failed"



def scan_folder(folder_path):
    global scan_results
    scan_results.clear()
    for root_dir, _, files in os.walk(folder_path):
        for file in files:
            full_path = os.path.join(root_dir, file)
            ext = os.path.splitext(file)[1].lower()

            try:
                stat = os.stat(full_path)
                created = datetime.datetime.fromtimestamp(stat.st_ctime)
                modified = datetime.datetime.fromtimestamp(stat.st_mtime)
                size = stat.st_size

                suspicious_name = is_suspicious_name(file)
                suspicious_content = is_suspicious_content(full_path) if ext not in image_extensions else False

                if ext in image_extensions:
                    gpt_result = analyze_image_with_gpt(file, created, modified, size)
                    status = f"Image - {gpt_result}"
                elif suspicious_name and suspicious_content:
                    status = "Suspicious (Name + Content)"
                elif suspicious_content:
                    status = "Suspicious (Content)"
                elif suspicious_name:
                    status = "Suspicious (Name)"
                else:
                    status = "Normal"

                scan_results.append((file, created, modified, size, status))
            except Exception as e:
                print("Error reading file:", e)


def browse_folder():
    folder_path = filedialog.askdirectory()
    if not folder_path:
        return
    scan_folder(folder_path)
    tree.delete(*tree.get_children())
    for row in scan_results:
        tree.insert("", tk.END, values=(row[0], row[1].strftime('%Y-%m-%d %H:%M:%S'),
                                        row[2].strftime('%Y-%m-%d %H:%M:%S'), row[3], row[4]))




def export_pdf():
    if not scan_results:
        messagebox.showwarning("Warning", "No data available to export!")
        return

    save_path = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF files", "*.pdf")])
    if save_path:
        try:
            pdf = FPDF()
            pdf.add_page()
            pdf.set_font("Arial", size=12)

            # Title
            pdf.cell(200, 10, txt="Recycle Bin Analysis Report", ln=True, align='C')
            pdf.ln(10)

            # Table headers
            pdf.set_font("Arial", 'B', 10)
            headers = ["File Name", "Created", "Modified", "Size", "Status"]
            col_widths = [60, 40, 40, 20, 30]

            for i, header in enumerate(headers):
                pdf.cell(col_widths[i], 10, header, border=1, align='C')
            pdf.ln()

            # Table rows
            pdf.set_font("Arial", size=9)
            for row in scan_results:
                pdf.cell(col_widths[0], 10, row[0][:30], border=1)  # File Name
                pdf.cell(col_widths[1], 10, row[1].strftime('%Y-%m-%d'), border=1)  # Created
                pdf.cell(col_widths[2], 10, row[2].strftime('%Y-%m-%d'), border=1)  # Modified
                pdf.cell(col_widths[3], 10, str(row[3]), border=1)  # Size
                pdf.cell(col_widths[4], 10, row[4], border=1)  # Status
                pdf.ln()

            pdf.output(save_path)
            messagebox.showinfo("Success", "PDF report exported successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export PDF: {e}")




def read_event_logs(log_type):
    logs = []
    try:
        hand = win32evtlog.OpenEventLog('localhost', log_type)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        events = win32evtlog.ReadEventLog(hand, flags, 0)
        for event in events[:30]:
            logs.append(f"[{log_type}] Source: {event.SourceName}, ID: {event.EventID}, Data: {event.StringInserts}")
    except Exception as e:
        logs.append(f"Error reading {log_type} logs: {e}")
    return logs


def analyze_logs():
    all_logs = read_event_logs("Application") + read_event_logs("System")
    prompt = "Analyze the following Windows logs:\n\n" + "\n".join(all_logs)
    try:
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a cybersecurity analyst."},
                {"role": "user", "content": prompt}
            ]
        )
        analysis = response.choices[0].message.content
        log_window = tk.Toplevel(root)
        log_window.title("Log Analysis Result")
        text = tk.Text(log_window, wrap="word", font=("Arial", 10))
        text.pack(expand=True, fill="both")
        text.insert(tk.END, analysis)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to analyze logs: {e}")


def is_suspicious(filename, extension, modified, created):
    if any(word in filename.lower() for word in suspicious_keywords):
        return True
    if extension.lower() in ['.exe', '.bat', '.vbs', '.scr', '.lnk', '.dll']:
        return True
    if abs((modified - created).total_seconds()) < 60:
        return True
    return False


def read_recycle_bin():
    global scan_results
    scan_results.clear()  # Clear old results

    try:
        pythoncom.CoInitialize()
        shell = win32com.client.Dispatch("Shell.Application")
        bin_folder = shell.Namespace(10)  # 10 = Recycle Bin
        items = bin_folder.Items()

        for item in items:
            name = item.Name
            path = item.Path
            try:
                created = datetime.datetime.fromtimestamp(os.path.getctime(path))
                modified = datetime.datetime.fromtimestamp(os.path.getmtime(path))
            except:
                created = modified = datetime.datetime.now()

            ext = os.path.splitext(name)[1]
            suspicious = is_suspicious(name, ext, modified, created)
            status = " Suspicious" if suspicious else " Normal"
            size = "-"  # Size not available from COM directly

            # ✅ Add result to scan_results for CSV export
            scan_results.append((name, created, modified, size, status))

            # ✅ Show in Treeview
            tree.insert("", tk.END, values=(
                name,
                created.strftime('%Y-%m-%d %H:%M:%S'),
                modified.strftime('%Y-%m-%d %H:%M:%S'),
                size,
                status
            ))

        messagebox.showinfo("Success", "Recycle Bin scanned and analyzed successfully.")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to read Recycle Bin: {str(e)}")



def launch_autopsy():
    try:
        autopsy_path = r"C:\Program Files\Autopsy-4.22.1\Desktop\bin\autopsy64.exe"
        if os.path.exists(autopsy_path):
            subprocess.Popen([autopsy_path])
        else:
            messagebox.showerror("Error", "Autopsy not found in the specified path.")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to launch Autopsy:\n{e}")




# Main Window
root = tk.Tk()
root.title("🔍 Digital MIR Forensics Investigation Tool")
root.geometry("1050x700")
root.configure(bg="#1E1E2E")  # Dark background

# Style for Buttons
def on_enter(e):
    e.widget['background'] = '#45A049'

def on_leave(e):
    e.widget['background'] = e.widget.default_bg

def create_button(text, command, color):
    btn = tk.Button(root, text=text, command=command, bg=color, fg="white",
                    font=("Arial", 13, "bold"), relief="flat", padx=10, pady=10, width=25)
    btn.default_bg = color
    btn.bind("<Enter>", on_enter)
    btn.bind("<Leave>", on_leave)
    return btn





def restart_app():
    python = sys.executable
    os.execl(python, python, *sys.argv)


# Title
title = tk.Label(root, text="Digital MIR Forensics Dashboard", font=("Arial", 20, "bold"), fg="#FFFFFF", bg="#1E1E2E")
title.pack(pady=15)

# Buttons

restart_btn = tk.Button(root, text="🔄 Restart App", command=restart_app, bg="#607D8B", fg="white", font=("Arial", 12, "bold"))
restart_btn.pack(pady=5)

browse_btn = create_button("📂 Scan Folder", browse_folder, "#4CAF50")
browse_btn.pack(pady=8)

log_btn = create_button("🧠 Analyze Logs", analyze_logs, "#3F51B5")
log_btn.pack(pady=8)

pdf_btn = create_button("📄 Export PDF Report", export_pdf, "#FF5722")
pdf_btn.pack(pady=8)

recycle_btn = create_button("♻️ Analyze Recycle Bin", read_recycle_bin, "#9C27B0")
recycle_btn.pack(pady=8)

autopsy_btn = create_button("🕵️ Launch Autopsy", launch_autopsy, "#607D8B")
autopsy_btn.pack(pady=8)


# Treeview Style
style = ttk.Style()
style.theme_use("clam")
style.configure("Treeview",
                background="#2E2E3E",
                foreground="white",
                rowheight=28,
                fieldbackground="#2E2E3E",
                font=("Arial", 11))
style.configure("Treeview.Heading",
                background="#44475A",
                foreground="white",
                font=("Arial", 12, "bold"))
style.map("Treeview", background=[('selected', '#6272A4')])

# Treeview Table
columns = ("File Name", "Created", "Modified", "Size (Bytes)", "Status")
tree_frame = tk.Frame(root, bg="#1E1E2E")
tree_frame.pack(fill="both", expand=True, pady=15, padx=20)

tree = ttk.Treeview(tree_frame, columns=columns, show="headings")
for col in columns:
    tree.heading(col, text=col)
    tree.column(col, width=200)
tree.pack(fill="both", expand=True)

# Add Scrollbar
scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=tree.yview)
tree.configure(yscroll=scrollbar.set)
scrollbar.pack(side="right", fill="y")

root.mainloop()



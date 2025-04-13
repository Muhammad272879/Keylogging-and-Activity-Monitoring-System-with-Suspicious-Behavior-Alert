import socket
import threading
import os
import json
from datetime import datetime
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
from PIL import Image, ImageTk, ImageOps
import io
import hashlib
import logging
import secrets
from PIL import ImageDraw

# Default configuration
DEFAULT_CONFIG = {
    "ADMIN_HOST": "192.168.0.1",  # Localhost for client compatibility
    "ADMIN_PORT": 12345,        # Matches client’s SERVER_PORT
    "TARGET_HOST": "192.168.0.1",
    "TARGET_PORT": 12346,
    "FIRST_TIME": True
}

# File paths
CONFIG_FILE = "config.json"
CREDENTIALS_FILE = "admin_credentials.json"
REMEMBER_ME_FILE = "remember_me.json"

# Ensure directories exist
LOG_DIR = "admin_logs"
SCREENSHOT_DIR = "screenshots"
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(SCREENSHOT_DIR, exist_ok=True)

# Global variables
server_running = True
pc_tabs = {}
sessions = {}

# Theme Colors
PRIMARY_BG = "#1e1e2f"
ACCENT_BLUE = "#007AFF"
SECONDARY_BG = "#2d2d44"
TEXT_COLOR = "#d3d3d3"
HIGHLIGHT_GREEN = "#00C853"
WARNING_RED = "#FF5252"
ACTIVE_PURPLE = "#6200EA"
TAB_GOLD = "#FFD740"
WHITE = "#FFFFFF"
BLACK = "#000000"

# Logging Setup
logging.basicConfig(filename=os.path.join(LOG_DIR, 'server.log'), level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Theme Setup
def setup_theme():
    style = ttk.Style()
    style.theme_use("clam")
    style.configure("TFrame", background=PRIMARY_BG)
    style.configure("TLabel", background=PRIMARY_BG, foreground=TEXT_COLOR, font=("Helvetica", 10))
    style.configure("TButton", background=ACCENT_BLUE, foreground=WHITE, borderwidth=1, padding=6, font=("Helvetica", 10, "bold"))
    style.configure("TNotebook", background=PRIMARY_BG)
    style.configure("TNotebook.Tab", background=SECONDARY_BG, foreground=TEXT_COLOR, padding=[8, 4], font=("Helvetica", 10))
    style.map("TButton", background=[("active", WARNING_RED)], foreground=[("active", WHITE)])
    style.map("TNotebook.Tab", background=[("selected", TAB_GOLD)], foreground=[("selected", BLACK)])

# Utility Functions
def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    return DEFAULT_CONFIG

def save_config(config):
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=4)

def is_first_time():
    config = load_config()
    return config.get("FIRST_TIME", True)

def set_first_time_complete():
    config = load_config()
    config["FIRST_TIME"] = False
    save_config(config)

def load_credentials():
    if os.path.exists(CREDENTIALS_FILE):
        with open(CREDENTIALS_FILE, "r") as f:
            return json.load(f)
    return None

def save_credentials(username, password, answer1, answer2):
    salt = secrets.token_hex(16)
    hashed_password = hashlib.sha256((password + salt).encode()).hexdigest()
    answer1_salt = secrets.token_hex(16)
    hashed_answer1 = hashlib.sha256((answer1 + answer1_salt).encode()).hexdigest()
    answer2_salt = secrets.token_hex(16)
    hashed_answer2 = hashlib.sha256((answer2 + answer2_salt).encode()).hexdigest()
    credentials = {
        "username": username,
        "password": hashed_password,
        "salt": salt,
        "security_answers": {
            "answer1": hashed_answer1,
            "answer1_salt": answer1_salt,
            "answer2": hashed_answer2,
            "answer2_salt": answer2_salt
        }
    }
    with open(CREDENTIALS_FILE, "w") as f:
        json.dump(credentials, f, indent=4)

def verify_password(stored_password, salt, provided_password):
    new_hash = hashlib.sha256((provided_password + salt).encode()).hexdigest()
    return new_hash == stored_password

def load_remember_me():
    if os.path.exists(REMEMBER_ME_FILE):
        with open(REMEMBER_ME_FILE, "r") as f:
            return json.load(f)
    return None

def save_remember_me(username, password):
    data = {"username": username, "password": password}
    with open(REMEMBER_ME_FILE, "w") as f:
        json.dump(data, f, indent=4)

def clear_remember_me():
    if os.path.exists(REMEMBER_ME_FILE):
        os.remove(REMEMBER_ME_FILE)

# GUI Functions
def create_dashboard():
    root = tk.Tk()
    root.title("Admin Server Dashboard")
    root.geometry("1020x910")
    root.config(bg=PRIMARY_BG)

    setup_theme()

    main_frame = ttk.Frame(root)
    main_frame.pack(fill="both", expand=True)

    sidebar_frame = ttk.Frame(main_frame, width=200, relief="raised", borderwidth=2)
    sidebar_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 2))

    LOGO_FILE = "user_logo.png"

    def make_circle_image(image):
        img = image.resize((50, 50), Image.Resampling.LANCZOS)
        mask = Image.new("L", (50, 50), 0)
        draw = ImageDraw.Draw(mask)
        draw.ellipse((0, 0, 50, 50), fill=255)
        output = Image.new("RGBA", (50, 50), (0, 0, 0, 0))
        output.paste(img, (0, 0), mask)
        return output

    def load_or_set_logo():
        if os.path.exists(LOGO_FILE):
            try:
                img = Image.open(LOGO_FILE)
                img = make_circle_image(img)
                return ImageTk.PhotoImage(img)
            except Exception as e:
                logging.error(f"Error loading logo: {e}")
        img = Image.new("RGBA", (50, 50), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        draw.ellipse((0, 0, 50, 50), fill=ACCENT_BLUE, outline=WHITE)
        return ImageTk.PhotoImage(img)

    def upload_logo(event=None):
        file_path = filedialog.askopenfilename(
            title="Select Logo Image",
            filetypes=(("Image Files", "*.png *.jpg *.jpeg *.bmp *.gif"), ("All Files", "*.*"))
        )
        if file_path:
            try:
                img = Image.open(file_path).convert("RGBA")
                circular_img = make_circle_image(img)
                circular_img.save(LOGO_FILE, "PNG")
                photo = ImageTk.PhotoImage(circular_img)
                logo_label.config(image=photo)
                logo_label.image = photo
                logging.info("New logo uploaded and saved.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to upload logo: {e}", icon="error")
                logging.error(f"Error uploading logo: {e}")

    logo_frame = ttk.Frame(sidebar_frame)
    logo_frame.pack(fill=tk.X, pady=20)
    logo_photo = load_or_set_logo()
    logo_label = tk.Label(logo_frame, image=logo_photo, bg=SECONDARY_BG, cursor="hand2", relief="groove", borderwidth=2)
    logo_label.image = logo_photo
    logo_label.pack(pady=5)
    logo_label.bind("<Button-1>", upload_logo)

    credentials = load_credentials()
    username = credentials["username"] if credentials else "Admin"
    profile_label = tk.Label(logo_frame, text=username, font=("Helvetica", 10, "bold"), bg=SECONDARY_BG, fg=TEXT_COLOR)
    profile_label.pack()

    def create_sidebar_button(frame, text, command):
        btn = ttk.Button(frame, text=text, command=command)
        btn.pack(fill=tk.X, pady=5, padx=10)
        return btn

    def show_help():
        help_window = tk.Toplevel()
        help_window.title("Help")
        help_window.geometry("600x400")
        help_window.config(bg=PRIMARY_BG)
        setup_theme()
        help_text = scrolledtext.ScrolledText(help_window, wrap=tk.WORD, bg=SECONDARY_BG, fg=TEXT_COLOR, font=("Helvetica", 10))
        help_text.pack(fill="both", expand=True, padx=15, pady=15)
        help_content = """
        Welcome to the Admin Server Dashboard Help!

        - Profile: Update your username and password.
        - Settings: Configure server host and port settings.
        - Screenshots: View screenshots captured from connected PCs.
        - View Record: Browse and search through log files.
        - Help: You're here! Get assistance with the dashboard.
        - Logout: Exit the dashboard and return to the login screen.

        For further assistance, contact support.
        """
        help_text.insert(tk.END, help_content)
        help_text.config(state=tk.DISABLED)

    create_sidebar_button(sidebar_frame, "Profile", lambda: open_profile_window(root))
    create_sidebar_button(sidebar_frame, "Screenshots", view_screenshots)
    create_sidebar_button(sidebar_frame, "View Record", view_record)
    create_sidebar_button(sidebar_frame, "Settings", create_config_window)
    create_sidebar_button(sidebar_frame, "Help", show_help)
    create_sidebar_button(sidebar_frame, "Logout", lambda: logout(root))

    content_frame = ttk.Frame(main_frame)
    content_frame.pack(side=tk.RIGHT, fill="both", expand=True, padx=15, pady=15)

    content_header = tk.Label(content_frame, text="Admin Server Dashboard", font=("Helvetica", 20, "bold"), bg=PRIMARY_BG, fg=TEXT_COLOR, pady=10)
    content_header.pack(fill=tk.X)

    button_frame = ttk.Frame(content_frame)
    button_frame.pack(fill=tk.X, pady=10)

    style = ttk.Style()
    style.configure("Stop.TButton", background=ACCENT_BLUE, foreground=WHITE, borderwidth=1, padding=6, font=("Helvetica", 10, "bold"))
    style.map("Stop.TButton", background=[("active", WARNING_RED)], foreground=[("active", WHITE)])

    start_button = ttk.Button(button_frame, text="Start Admin Server",
                              command=lambda: [start_admin_server(tab_control, start_button, stop_button),
                                               stop_button.configure(style="Stop.TButton", state=tk.NORMAL),
                                               style.configure("Stop.TButton", background=WARNING_RED)])
    start_button.grid(row=0, column=0, padx=5, pady=5)

    stop_button = ttk.Button(button_frame, text="Stop Admin Server", style="Stop.TButton", state=tk.DISABLED,
                             command=lambda: [stop_admin_server(start_button, stop_button),
                                              stop_button.configure(state=tk.DISABLED),
                                              style.configure("Stop.TButton", background=ACCENT_BLUE)])
    stop_button.grid(row=0, column=1, padx=5, pady=5)

    search_button = ttk.Button(button_frame, text="Search", command=search_logs)
    search_button.grid(row=0, column=2, padx=5, pady=5, sticky="e")

    button_frame.grid_columnconfigure(2, weight=1)

    tab_control = ttk.Notebook(content_frame)
    tab_control.pack(expand=True, fill="both", pady=15)

    placeholder_tab = ttk.Frame(tab_control)
    tab_control.add(placeholder_tab, text="PC Monitor")
    placeholder_label = tk.Label(placeholder_tab, text="No PCs connected yet", font=("Helvetica", 16), bg=PRIMARY_BG, fg=TEXT_COLOR)
    placeholder_label.pack(expand=True)

    root.mainloop()

def view_screenshots():
    screenshot_window = tk.Toplevel()
    screenshot_window.title("Screenshots")
    screenshot_window.geometry("870x670")
    screenshot_window.config(bg=PRIMARY_BG)
    setup_theme()

    # Create a canvas with scrollbars
    canvas = tk.Canvas(screenshot_window, bg=SECONDARY_BG, width=850, height=580)  # Slightly smaller than window to fit scrollbars
    v_scrollbar = ttk.Scrollbar(screenshot_window, orient="vertical", command=canvas.yview)
    h_scrollbar = ttk.Scrollbar(screenshot_window, orient="horizontal", command=canvas.xview)
    scrollable_frame = ttk.Frame(canvas)

    # Configure canvas scrolling
    canvas.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
    scrollable_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))

    # Pack the canvas and scrollbars
    h_scrollbar.pack(side=tk.BOTTOM, fill=tk.X)
    v_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    canvas.pack(side=tk.LEFT, fill="both", expand=True)

    # Create a window inside the canvas for the scrollable frame
    canvas_window = canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")

    # Load and display screenshots
    screenshots = [f for f in os.listdir(SCREENSHOT_DIR) if f.endswith(".png")]
    if not screenshots:
        tk.Label(scrollable_frame, text="No screenshots available", font=("Helvetica", 10),
                 bg=SECONDARY_BG, fg=TEXT_COLOR).pack(pady=20)
    else:
        for screenshot in screenshots:
            img_path = os.path.join(SCREENSHOT_DIR, screenshot)
            try:
                # Open the image without resizing to preserve original size
                img = Image.open(img_path)
                photo = ImageTk.PhotoImage(img)

                # Display the image
                lbl = tk.Label(scrollable_frame, image=photo, bg=SECONDARY_BG)
                lbl.image = photo  # Keep a reference to avoid garbage collection
                lbl.pack(pady=5)

                # Add filename label below the image
                tk.Label(scrollable_frame, text=screenshot, font=("Helvetica", 10),
                         bg=SECONDARY_BG, fg=TEXT_COLOR).pack(pady=5)
            except Exception as e:
                logging.error(f"Error loading screenshot {screenshot}: {e}")
                tk.Label(scrollable_frame, text=f"Error loading {screenshot}", font=("Helvetica", 10),
                         bg=SECONDARY_BG, fg=WARNING_RED).pack(pady=5)

    # Function to update scroll region after rendering
    def update_scroll_region():
        screenshot_window.update_idletasks()  # Ensure all widgets are rendered
        bbox = canvas.bbox("all")  # Get bounding box of all canvas items
        if bbox:
            canvas.configure(scrollregion=bbox)
            print(f"Scroll region updated to: {bbox}")
        else:
            print("No bounding box available for scroll region")

        # Ensure the canvas window width matches the canvas width for horizontal scrolling
        canvas.itemconfig(canvas_window, width=canvas.winfo_width())

    # Schedule the scroll region update after the GUI is fully rendered
    screenshot_window.after(100, update_scroll_region)

    # Optional: Bind mouse wheel scrolling (works on Windows, may need adjustment for other OS)
    def _on_mousewheel(event):
        canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

    canvas.bind_all("<MouseWheel>", _on_mousewheel)

def logout(root):
    if messagebox.askyesno("Logout", "Are you sure you want to logout?"):
        root.destroy()
        create_login_window()

def open_profile_window(parent):
    def save_profile_changes():
        new_username = username_entry.get()
        current_password = current_password_entry.get()
        new_password = new_password_entry.get()
        confirm_password = confirm_password_entry.get()
        if not all([new_username, current_password, new_password, confirm_password]):
            messagebox.showerror("Error", "All fields are required!", icon="error")
            return
        credentials = load_credentials()
        if not credentials or not verify_password(credentials["password"], credentials["salt"], current_password):
            messagebox.showerror("Error", "Current password is incorrect!", icon="error")
            return
        if new_password != confirm_password:
            messagebox.showerror("Error", "New passwords do not match!", icon="error")
            return
        salt = secrets.token_hex(16)
        hashed_password = hashlib.sha256((new_password + salt).encode()).hexdigest()
        credentials["username"] = new_username
        credentials["password"] = hashed_password
        credentials["salt"] = salt
        with open(CREDENTIALS_FILE, "w") as f:
            json.dump(credentials, f, indent=4)
        messagebox.showinfo("Success", "Profile updated successfully!", icon="info")
        profile_window.destroy()

    profile_window = tk.Toplevel(parent)
    profile_window.title("Update Profile")
    profile_window.geometry("400x350")
    profile_window.config(bg=PRIMARY_BG)
    setup_theme()
    profile_frame = ttk.Frame(profile_window, padding=20)
    profile_frame.pack(expand=True)
    tk.Label(profile_frame, text="Update Profile", font=("Helvetica", 14, "bold"), bg=PRIMARY_BG, fg=TEXT_COLOR).grid(row=0, column=0, columnspan=2, pady=10)
    tk.Label(profile_frame, text="New Username:", bg=PRIMARY_BG, fg=TEXT_COLOR).grid(row=1, column=0, pady=10, sticky="e")
    username_entry = ttk.Entry(profile_frame, width=30)
    username_entry.insert(0, load_credentials()["username"])
    username_entry.grid(row=1, column=1, pady=10)
    tk.Label(profile_frame, text="Current Password:", bg=PRIMARY_BG, fg=TEXT_COLOR).grid(row=2, column=0, pady=10, sticky="e")
    current_password_entry = ttk.Entry(profile_frame, show="*", width=30)
    current_password_entry.grid(row=2, column=1, pady=10)
    tk.Label(profile_frame, text="New Password:", bg=PRIMARY_BG, fg=TEXT_COLOR).grid(row=3, column=0, pady=10, sticky="e")
    new_password_entry = ttk.Entry(profile_frame, show="*", width=30)
    new_password_entry.grid(row=3, column=1, pady=10)
    tk.Label(profile_frame, text="Confirm New Password:", bg=PRIMARY_BG, fg=TEXT_COLOR).grid(row=4, column=0, pady=10, sticky="e")
    confirm_password_entry = ttk.Entry(profile_frame, show="*", width=30)
    confirm_password_entry.grid(row=4, column=1, pady=10)
    save_button = ttk.Button(profile_frame, text="Save Changes", command=save_profile_changes)
    save_button.grid(row=5, column=0, columnspan=2, pady=20)

def create_login_window():
    """Create the login window with dark background and original button theme."""
    def validate_login():
        username = username_entry.get()
        password = password_entry.get()
        credentials = load_credentials()
        if credentials and username == credentials["username"]:
            if verify_password(credentials["password"], credentials["salt"], password):
                if remember_var.get():
                    save_remember_me(username, password)
                else:
                    clear_remember_me()
                login_window.destroy()
                if is_first_time():
                    create_config_window_after_login()
                else:
                    create_dashboard()
            else:
                messagebox.showerror("Login Failed", "Invalid password!", icon="error")
        else:
            messagebox.showerror("Login Failed", "Invalid username or password!", icon="error")

    def forgot_password():
        def verify_answers():
            answer1 = answer1_entry.get()
            answer2 = answer2_entry.get()
            credentials = load_credentials()
            if not credentials:
                messagebox.showerror("Error", "No account exists!", icon="error")
                return
            stored_answer1 = credentials["security_answers"]["answer1"]
            answer1_salt = credentials["security_answers"]["answer1_salt"]
            stored_answer2 = credentials["security_answers"]["answer2"]
            answer2_salt = credentials["security_answers"]["answer2_salt"]
            hashed_answer1 = hashlib.sha256((answer1 + answer1_salt).encode()).hexdigest()
            hashed_answer2 = hashlib.sha256((answer2 + answer2_salt).encode()).hexdigest()
            if hashed_answer1 == stored_answer1 and hashed_answer2 == stored_answer2:
                reset_password_window(credentials)
                forgot_window.destroy()
            else:
                messagebox.showerror("Error", "Incorrect answers!", icon="error")

        def reset_password_window(credentials):
            def save_new_password():
                new_password = new_password_entry.get()
                confirm_password = confirm_password_entry.get()
                if new_password != confirm_password:
                    messagebox.showerror("Error", "Passwords do not match!", icon="error")
                    return
                salt = secrets.token_hex(16)
                hashed_password = hashlib.sha256((new_password + salt).encode()).hexdigest()
                credentials["password"] = hashed_password
                credentials["salt"] = salt
                with open(CREDENTIALS_FILE, "w") as f:
                    json.dump(credentials, f, indent=4)
                messagebox.showinfo("Success", "Password reset successfully!", icon="info")
                reset_window.destroy()

            reset_window = tk.Toplevel()
            reset_window.title("Reset Password")
            reset_window.geometry("400x300")
            reset_window.config(bg=PRIMARY_BG)
            setup_theme()
            reset_frame = ttk.Frame(reset_window, padding=20)
            reset_frame.pack(expand=True)
            tk.Label(reset_frame, text="Reset Password", font=("Helvetica", 14, "bold"), bg=PRIMARY_BG, fg=TEXT_COLOR).grid(row=0, column=0, columnspan=2, pady=10)
            tk.Label(reset_frame, text="New Password:", bg=PRIMARY_BG, fg=TEXT_COLOR).grid(row=1, column=0, pady=10, sticky="e")
            new_password_entry = ttk.Entry(reset_frame, show="*", width=30)
            new_password_entry.grid(row=1, column=1, pady=10)
            tk.Label(reset_frame, text="Confirm Password:", bg=PRIMARY_BG, fg=TEXT_COLOR).grid(row=2, column=0, pady=10, sticky="e")
            confirm_password_entry = ttk.Entry(reset_frame, show="*", width=30)
            confirm_password_entry.grid(row=2, column=1, pady=10)
            reset_button = ttk.Button(reset_frame, text="Reset", command=save_new_password)
            reset_button.grid(row=3, column=0, columnspan=2, pady=20)

        forgot_window = tk.Toplevel()
        forgot_window.title("Forgot Password")
        forgot_window.geometry("400x350")
        forgot_window.config(bg=PRIMARY_BG)
        setup_theme()
        forgot_frame = ttk.Frame(forgot_window, padding=20)
        forgot_frame.pack(expand=True)
        tk.Label(forgot_frame, text="Forgot Password", font=("Helvetica", 14, "bold"), bg=PRIMARY_BG, fg=TEXT_COLOR).grid(row=0, column=0, columnspan=2, pady=10)
        tk.Label(forgot_frame, text="Answer the security questions to reset your password.", bg=PRIMARY_BG, fg=TEXT_COLOR).grid(row=1, column=0, columnspan=2, pady=5)
        tk.Label(forgot_frame, text="What is your email?", bg=PRIMARY_BG, fg=TEXT_COLOR).grid(row=2, column=0, pady=10, sticky="e")
        answer1_entry = ttk.Entry(forgot_frame, width=30)
        answer1_entry.grid(row=2, column=1, pady=10)
        tk.Label(forgot_frame, text="What is your code?", bg=PRIMARY_BG, fg=TEXT_COLOR).grid(row=3, column=0, pady=10, sticky="e")
        answer2_entry = ttk.Entry(forgot_frame, width=30)
        answer2_entry.grid(row=3, column=1, pady=10)
        verify_button = ttk.Button(forgot_frame, text="Verify", command=verify_answers)
        verify_button.grid(row=4, column=0, columnspan=2, pady=20)

    def create_config_window_after_login():
        """Create the configuration window after login for first time setup."""
        def save_configuration():
            config = {
                "ADMIN_HOST": admin_host_entry.get(),
                "ADMIN_PORT": int(admin_port_entry.get()),
                "TARGET_HOST": target_host_entry.get(),
                "TARGET_PORT": int(target_port_entry.get()),
                "FIRST_TIME": False
            }
            save_config(config)
            messagebox.showinfo("Success", "Configuration saved successfully! You can now use the dashboard.", icon="info")
            config_window.destroy()
            create_dashboard()

        config = load_config()
        config_window = tk.Tk()
        config_window.title("First Time Configuration")
        config_window.geometry("600x450")
        config_window.config(bg=PRIMARY_BG)
        setup_theme()
        config_frame = ttk.Frame(config_window, padding=20)
        config_frame.pack(expand=True)
        tk.Label(config_frame, text="Server Configuration", font=("Helvetica", 18, "bold"), bg=PRIMARY_BG, fg=TEXT_COLOR).grid(row=0, column=0, columnspan=2, pady=15)
        tk.Label(config_frame, text="Please configure the IP addresses and ports to proceed.", bg=PRIMARY_BG, fg=TEXT_COLOR).grid(row=1, column=0, columnspan=2, pady=5)
        tk.Label(config_frame, text="Admin Host:", bg=PRIMARY_BG, fg=TEXT_COLOR).grid(row=2, column=0, pady=10, sticky="e")
        admin_host_entry = ttk.Entry(config_frame, width=30)
        admin_host_entry.insert(0, config["ADMIN_HOST"])
        admin_host_entry.grid(row=2, column=1, pady=10)
        tk.Label(config_frame, text="Admin Port:", bg=PRIMARY_BG, fg=TEXT_COLOR).grid(row=3, column=0, pady=10, sticky="e")
        admin_port_entry = ttk.Entry(config_frame, width=30)
        admin_port_entry.insert(0, str(config["ADMIN_PORT"]))
        admin_port_entry.grid(row=3, column=1, pady=10)
        tk.Label(config_frame, text="Target Host:", bg=PRIMARY_BG, fg=TEXT_COLOR).grid(row=4, column=0, pady=10, sticky="e")
        target_host_entry = ttk.Entry(config_frame, width=30)
        target_host_entry.insert(0, config["TARGET_HOST"])
        target_host_entry.grid(row=4, column=1, pady=10)
        tk.Label(config_frame, text="Target Port:", bg=PRIMARY_BG, fg=TEXT_COLOR).grid(row=5, column=0, pady=10, sticky="e")
        target_port_entry = ttk.Entry(config_frame, width=30)
        target_port_entry.insert(0, str(config["TARGET_PORT"]))
        target_port_entry.grid(row=5, column=1, pady=10)
        save_button = ttk.Button(config_frame, text="Save and Proceed", command=save_configuration)
        save_button.grid(row=6, column=0, columnspan=2, pady=20)
        config_window.mainloop()

    remembered = load_remember_me()
    default_username = remembered.get("username", "") if remembered else ""
    default_password = remembered.get("password", "") if remembered else ""

    login_window = tk.Tk()
    login_window.title("Admin Login")
    login_window.geometry("600x450")
    login_window.config(bg=PRIMARY_BG)
    setup_theme()
    style = ttk.Style()
    style.configure("Login.TButton", background=ACTIVE_PURPLE, foreground=WHITE, borderwidth=1, padding=6, font=("Helvetica", 10, "bold"))
    style.map("Login.TButton", background=[("active", WARNING_RED)], foreground=[("active", WHITE)])
    login_frame = ttk.Frame(login_window, padding=20)
    login_frame.pack(expand=True)
    # Swapped positions: "Keylogging" first, "LOGIN" second
    header_label = tk.Label(login_frame, text="Keylogging and Activity Monitoring System", font=("Helvetica", 20, "bold italic"), bg=PRIMARY_BG, fg=HIGHLIGHT_GREEN, pady=10)
    header_label.grid(row=0, column=0, columnspan=2)
    login_title = tk.Label(login_frame, text="LOGIN", font=("Helvetica", 24, "bold"), bg=PRIMARY_BG, fg=TEXT_COLOR, pady=5)
    login_title.grid(row=1, column=0, columnspan=2)
    username_label = tk.Label(login_frame, text="Username:", bg=PRIMARY_BG, fg=TEXT_COLOR)
    username_label.grid(row=2, column=0, padx=5, pady=5, sticky="e")
    username_entry = ttk.Entry(login_frame, width=30)
    username_entry.insert(0, default_username)
    username_entry.grid(row=2, column=1, padx=5, pady=5, sticky="w")
    password_label = tk.Label(login_frame, text="Password:", bg=PRIMARY_BG, fg=TEXT_COLOR)
    password_label.grid(row=3, column=0, padx=5, pady=5, sticky="e")
    password_entry = ttk.Entry(login_frame, show="*", width=30)
    password_entry.insert(0, default_password)
    password_entry.grid(row=3, column=1, padx=5, pady=5, sticky="w")
    remember_var = tk.BooleanVar(value=bool(remembered))
    remember_check = ttk.Checkbutton(login_frame, text="Remember Me", variable=remember_var, style="TCheckbutton", command=lambda: None)
    remember_check.grid(row=4, column=0, columnspan=2, pady=5)
    forgot_label = tk.Label(login_frame, text="Forgot Password?", bg=PRIMARY_BG, fg=ACCENT_BLUE, font=("Helvetica", 9, "underline"), cursor="hand2")
    forgot_label.grid(row=5, column=0, columnspan=2, pady=5)
    forgot_label.bind("<Button-1>", lambda e: forgot_password())
    login_button = ttk.Button(login_frame, text="Login", command=validate_login, style="Login.TButton")
    login_button.grid(row=6, column=0, columnspan=2, pady=20)
    login_window.mainloop()

def create_signup_window():
    def validate_signup():
        username = username_entry.get()
        password = password_entry.get()
        confirm_password = confirm_password_entry.get()
        answer1 = answer1_entry.get()
        answer2 = answer2_entry.get()
        if not all([username, password, confirm_password, answer1, answer2]):
            messagebox.showerror("Error", "All fields are required!", icon="error")
            return
        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match!", icon="error")
            return
        save_credentials(username, password, answer1, answer2)
        messagebox.showinfo("Success", "Admin account created successfully!", icon="info")
        signup_window.destroy()
        create_login_window()

    signup_window = tk.Tk()
    signup_window.title("Admin SignUp")
    signup_window.geometry("600x550")
    signup_window.config(bg=PRIMARY_BG)
    setup_theme()
    signup_frame = ttk.Frame(signup_window, padding=20)
    signup_frame.pack(expand=True)
    tk.Label(signup_frame, text="Admin SignUp", font=("Helvetica", 18, "bold"), bg=PRIMARY_BG, fg=TEXT_COLOR).grid(row=0, column=0, columnspan=2, pady=15)
    tk.Label(signup_frame, text="Username:", bg=PRIMARY_BG, fg=TEXT_COLOR).grid(row=1, column=0, pady=10, sticky="e")
    username_entry = ttk.Entry(signup_frame, width=30)
    username_entry.grid(row=1, column=1, pady=10)
    tk.Label(signup_frame, text="Password:", bg=PRIMARY_BG, fg=TEXT_COLOR).grid(row=2, column=0, pady=10, sticky="e")
    password_entry = ttk.Entry(signup_frame, show="*", width=30)
    password_entry.grid(row=2, column=1, pady=10)
    tk.Label(signup_frame, text="Confirm Password:", bg=PRIMARY_BG, fg=TEXT_COLOR).grid(row=3, column=0, pady=10, sticky="e")
    confirm_password_entry = ttk.Entry(signup_frame, show="*", width=30)
    confirm_password_entry.grid(row=3, column=1, pady=10)
    tk.Label(signup_frame, text="Security Question 1: What is your email?", bg=PRIMARY_BG, fg=TEXT_COLOR).grid(row=4, column=0, pady=10, sticky="e")
    answer1_entry = ttk.Entry(signup_frame, width=30)
    answer1_entry.grid(row=4, column=1, pady=10)
    tk.Label(signup_frame, text="Security Question 2: What is your code?", bg=PRIMARY_BG, fg=TEXT_COLOR).grid(row=5, column=0, pady=10, sticky="e")
    answer2_entry = ttk.Entry(signup_frame, width=30)
    answer2_entry.grid(row=5, column=1, pady=10)
    signup_button = ttk.Button(signup_frame, text="Sign Up", command=validate_signup)
    signup_button.grid(row=6, column=0, columnspan=2, pady=20)
    signup_window.mainloop()

def create_config_window():
    def save_configuration():
        config = {
            "ADMIN_HOST": admin_host_entry.get(),
            "ADMIN_PORT": int(admin_port_entry.get()),
            "TARGET_HOST": target_host_entry.get(),
            "TARGET_PORT": int(target_port_entry.get()),
            "FIRST_TIME": load_config()["FIRST_TIME"]
        }
        save_config(config)
        messagebox.showinfo("Success", "Configuration saved successfully!", icon="info")
        config_window.destroy()

    config = load_config()
    config_window = tk.Tk()
    config_window.title("Configuration")
    config_window.geometry("300x300")
    config_window.config(bg=PRIMARY_BG)
    config_window.resizable(False, False)
    setup_theme()

    canvas = tk.Canvas(config_window, width=300, height=300, highlightthickness=0)
    canvas.pack(fill="both", expand=True)
    gradient_colors = ["#1e1e2f", "#2d2d44"]
    for i in range(300):
        color = f"#{int(int(gradient_colors[0][1:3], 16) + (int(gradient_colors[1][1:3], 16) - int(gradient_colors[0][1:3], 16)) * i / 300):02x}" \
                f"{int(int(gradient_colors[0][3:5], 16) + (int(gradient_colors[1][3:5], 16) - int(gradient_colors[0][3:5], 16)) * i / 300):02x}" \
                f"{int(int(gradient_colors[0][5:7], 16) + (int(gradient_colors[1][5:7], 16) - int(gradient_colors[0][5:7], 16)) * i / 300):02x}"
        canvas.create_line(0, i, 300, i, fill=color)

    config_frame = ttk.Frame(config_window, padding=8, style="Card.TFrame")
    config_frame.place(relx=0.5, rely=0.5, anchor="center", width=260, height=240)

    style = ttk.Style()
    style.configure("Card.TFrame", background=SECONDARY_BG, relief="flat")
    style.configure("Custom.TLabel", background=SECONDARY_BG, foreground=TEXT_COLOR, font=("Helvetica", 8))
    style.configure("Title.TLabel", background=SECONDARY_BG, foreground=HIGHLIGHT_GREEN, font=("Helvetica", 10, "bold italic"))
    style.configure("Custom.TEntry", font=("Helvetica", 7))
    style.configure("Glow.TButton", background=ACCENT_BLUE, foreground=WHITE, font=("Helvetica", 8, "bold"), borderwidth=0, padding=4)
    style.map("Glow.TButton", background=[("active", ACTIVE_PURPLE)], foreground=[("active", WHITE)])

    title_label = ttk.Label(config_frame, text="Server Configuration", style="Title.TLabel")
    title_label.grid(row=0, column=0, columnspan=2, pady=(0, 8))

    fields = [
        ("Admin Host:", "ADMIN_HOST", admin_host_entry := ttk.Entry(config_frame, width=15, style="Custom.TEntry")),
        ("Admin Port:", "ADMIN_PORT", admin_port_entry := ttk.Entry(config_frame, width=15, style="Custom.TEntry")),
        ("Target Host:", "TARGET_HOST", target_host_entry := ttk.Entry(config_frame, width=15, style="Custom.TEntry")),
        ("Target Port:", "TARGET_PORT", target_port_entry := ttk.Entry(config_frame, width=15, style="Custom.TEntry"))
    ]

    for i, (label_text, config_key, entry) in enumerate(fields, start=1):
        label = ttk.Label(config_frame, text=label_text, style="Custom.TLabel")
        label.grid(row=i, column=0, pady=6, padx=(0, 5), sticky="e")
        entry.insert(0, str(config[config_key]))
        entry.grid(row=i, column=1, pady=6, sticky="w")
        entry.bind("<Enter>", lambda e, ent=entry: ent.configure(style="Hover.TEntry"))
        entry.bind("<Leave>", lambda e, ent=entry: ent.configure(style="Custom.TEntry"))
        style.configure("Hover.TEntry", fieldbackground=TAB_GOLD, foreground=BLACK)

    save_button = ttk.Button(config_frame, text="Save Configuration", command=save_configuration, style="Glow.TButton")
    save_button.grid(row=len(fields) + 1, column=0, columnspan=2, pady=12)

    def glow_effect():
        current_bg = save_button.cget("background")
        if current_bg == ACCENT_BLUE:
            style.configure("Glow.TButton", background=ACTIVE_PURPLE)
        else:
            style.configure("Glow.TButton", background=ACCENT_BLUE)
        config_window.after(1000, glow_effect)

    glow_effect()

    canvas.create_oval(10, 10, 25, 25, fill=TAB_GOLD, outline="")
    canvas.create_oval(275, 275, 295, 295, fill=HIGHLIGHT_GREEN, outline="")

    config_window.mainloop()

def view_record():
    log_file = filedialog.askopenfilename(initialdir=LOG_DIR, title="Select Log File", filetypes=(("Log Files", "*.log"), ("All Files", "*.*")))
    if log_file:
        with open(log_file, "r") as f:
            log_content = f.read()
        log_window = tk.Toplevel()
        log_window.title("View Log File")
        log_window.geometry("800x600")
        log_window.config(bg=PRIMARY_BG)
        setup_theme()
        log_text = scrolledtext.ScrolledText(log_window, wrap=tk.WORD, bg=SECONDARY_BG, fg=TEXT_COLOR, font=("Helvetica", 10))
        log_text.pack(fill="both", expand=True, padx=15, pady=15)
        log_text.insert(tk.END, log_content)
        log_text.config(state=tk.DISABLED)
        def search_text():
            search_query = search_entry.get().lower()
            if not search_query:
                messagebox.showwarning("Search", "Please enter a search query!", icon="warning")
                return
            log_text.tag_remove("highlight", "1.0", tk.END)
            matches = []
            start_index = "1.0"
            while True:
                start_index = log_text.search(search_query, start_index, nocase=True, stopindex=tk.END)
                if not start_index:
                    break
                end_index = f"{start_index}+{len(search_query)}c"
                matches.append((start_index, end_index))
                start_index = end_index
            for match_start, match_end in matches:
                log_text.tag_add("highlight", match_start, match_end)
            log_text.tag_config("highlight", background=HIGHLIGHT_GREEN, foreground=TEXT_COLOR)
            match_count_label.config(text=f"Matches: {len(matches)}")
            current_match_index = 0
            def next_match():
                nonlocal current_match_index
                if matches:
                    current_match_index = (current_match_index + 1) % len(matches)
                    show_match(current_match_index)
            def prev_match():
                nonlocal current_match_index
                if matches:
                    current_match_index = (current_match_index - 1) % len(matches)
                    show_match(current_match_index)
            def show_match(index):
                log_text.tag_remove("current_match", "1.0", tk.END)
                match_start, match_end = matches[index]
                log_text.tag_add("current_match", match_start, match_end)
                log_text.tag_config("current_match", background=ACTIVE_PURPLE, foreground=WHITE)
                log_text.see(match_start)
                match_index_label.config(text=f"{index + 1} of {len(matches)}")
            next_button.config(command=next_match)
            prev_button.config(command=prev_match)
        search_frame = ttk.Frame(log_window)
        search_frame.pack(fill=tk.X, padx=15, pady=5)
        search_label = ttk.Label(search_frame, text="Search:")
        search_label.pack(side=tk.LEFT)
        search_entry = ttk.Entry(search_frame, width=40)
        search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        search_button = ttk.Button(search_frame, text="Search", command=search_text)
        search_button.pack(side=tk.LEFT)
        match_count_label = ttk.Label(log_window, text="Matches: 0")
        match_count_label.pack(pady=5)
        match_index_label = ttk.Label(log_window, text="0 of 0")
        match_index_label.pack(pady=5)
        nav_frame = ttk.Frame(log_window)
        nav_frame.pack(fill=tk.X, padx=15, pady=5)
        prev_button = ttk.Button(nav_frame, text="Previous")
        prev_button.pack(side=tk.LEFT, padx=5)
        next_button = ttk.Button(nav_frame, text="Next")
        next_button.pack(side=tk.LEFT, padx=5)

def search_logs():
    def perform_search():
        query = search_entry.get().lower()
        if not query:
            messagebox.showwarning("Search", "Please enter a search query!", icon="warning")
            return
        results = []
        for root_dir, _, files in os.walk(LOG_DIR):
            for file in files:
                if file.endswith(".log"):
                    file_path = os.path.join(root_dir, file)
                    with open(file_path, "r") as f:
                        lines = f.readlines()
                    for line in lines:
                        if query in line.lower():
                            results.append(f"[{file}] {line.strip()}")
        if results:
            result_window = tk.Toplevel()
            result_window.title("Search Results")
            result_window.geometry("800x600")
            result_window.config(bg=PRIMARY_BG)
            setup_theme()
            result_text = scrolledtext.ScrolledText(result_window, wrap=tk.WORD, bg=SECONDARY_BG, fg=TEXT_COLOR, font=("Helvetica", 10))
            result_text.pack(fill="both", expand=True, padx=15, pady=15)
            for result in results:
                result_text.insert(tk.END, result + "\n")
            result_text.config(state=tk.DISABLED)
        else:
            messagebox.showinfo("Search Results", "No matches found.", icon="info")
    search_window = tk.Toplevel()
    search_window.title("Search")
    search_window.geometry("400x150")
    search_window.config(bg=PRIMARY_BG)
    setup_theme()
    search_label = tk.Label(search_window, text="Enter search query:", bg=PRIMARY_BG, fg=TEXT_COLOR, font=("Helvetica", 10))
    search_label.pack(pady=10)
    search_entry = ttk.Entry(search_window, width=40)
    search_entry.pack(pady=5)
    search_button = ttk.Button(search_window, text="Search", command=perform_search)
    search_button.pack(pady=10)

def log_text_data(client_ip, data_type, data, log_widget):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_file = os.path.join(LOG_DIR, f"{client_ip}_{data_type}.log")
    log_message = f"{timestamp} - {data_type}: {data}"
    with open(log_file, "a") as log:
        log.write(log_message + "\n")
    # Thread-safe GUI update
    log_widget.winfo_toplevel().after(0, lambda: [
        log_widget.insert(tk.END, log_message + "\n"),
        log_widget.see(tk.END)
    ])
    logging.info(f"Logged {data_type} from {client_ip}: {data}")

def log_suspicious_activity(client_ip, data, log_widget):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_file = os.path.join(LOG_DIR, f"{client_ip}_suspicious_activity.log")
    with open(log_file, "a") as log:
        log.write(f"{timestamp} - Suspicious Activity: {data}\n")
    log_message = f"{timestamp} - Suspicious Activity: {data}"
    log_widget.winfo_toplevel().after(0, lambda: [
        log_widget.insert(tk.END, log_message + "\n", 'suspicious'),
        log_widget.tag_config('suspicious', foreground=WARNING_RED),
        log_widget.see(tk.END)
    ])
    messagebox.showwarning("Suspicious Activity Detected", f"Suspicious activity detected from {client_ip}:\n{data}", icon="warning")
    logging.warning(f"Suspicious activity from {client_ip}: {data}")

def save_screenshot(client_ip, binary_data, canvas):
    try:
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        screenshot_path = os.path.join(SCREENSHOT_DIR, f"{client_ip}_screenshot_{timestamp}.png")
        with open(screenshot_path, "wb") as f:
            f.write(binary_data)
        img = Image.open(io.BytesIO(binary_data))
        photo = ImageTk.PhotoImage(img)
        canvas.winfo_toplevel().after(0, lambda: [
            canvas.delete("all"),
            canvas.create_image(400, 300, image=photo, anchor=tk.CENTER),
            setattr(canvas, 'image', photo)
        ])
        logging.info(f"Screenshot saved from {client_ip}")
    except Exception as e:
        logging.error(f"Error saving screenshot for {client_ip}: {e}")

def start_session(client_ip):
    sessions[client_ip] = {"start_time": datetime.now(), "last_activity": datetime.now(), "logs": []}
    logging.info(f"Session started for {client_ip}")

def end_session(client_ip):
    if client_ip in sessions:
        session = sessions[client_ip]
        duration = datetime.now() - session['start_time']
        session['end_time'] = datetime.now()
        session['duration'] = str(duration)
        del sessions[client_ip]
        logging.info(f"Session ended for {client_ip}. Duration: {duration}")

def update_session_activity(client_ip):
    if client_ip in sessions:
        sessions[client_ip]['last_activity'] = datetime.now()

def create_log_tab(tab_control, title):
    log_tab = ttk.Frame(tab_control)
    tab_control.add(log_tab, text=title)
    log_widget = scrolledtext.ScrolledText(log_tab, wrap=tk.WORD, bg=SECONDARY_BG, fg=TEXT_COLOR, font=("Helvetica", 10))
    log_widget.pack(fill="both", expand=True, padx=15, pady=15)
    return log_widget

def create_screenshot_tab(tab_control):
    screenshot_tab = ttk.Frame(tab_control)
    tab_control.add(screenshot_tab, text="Screenshot")
    canvas = tk.Canvas(screenshot_tab, width=800, height=600, relief=tk.SUNKEN, bg=SECONDARY_BG)
    canvas.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
    canvas.create_text(400, 300, text="No screenshot received yet", font=("Helvetica", 16), fill=TEXT_COLOR)
    return canvas

def get_pc_name_from_ip(client_ip):
    last_octet = client_ip.split('.')[-1]
    return f"PC {last_octet}"

def handle_client(client_socket, client_ip, main_tab_control):
    global pc_tabs
    start_session(client_ip)
    if not pc_tabs:
        for i in range(main_tab_control.index("end")):
            if main_tab_control.tab(i, "text") == "PC Monitor":
                main_tab_control.forget(i)
                break
    pc_name = get_pc_name_from_ip(client_ip)
    if client_ip not in pc_tabs:
        pc_tab = ttk.Frame(main_tab_control)
        main_tab_control.add(pc_tab, text=pc_name)
        main_tab_control.select(pc_tab)
        pc_tab_control = ttk.Notebook(pc_tab)
        pc_tab_control.pack(fill="both", expand=True, padx=15, pady=15)
        window_log = create_log_tab(pc_tab_control, "Window Activity Log")
        keylog_log = create_log_tab(pc_tab_control, "Keylog")
        process_log = create_log_tab(pc_tab_control, "Processes Log")
        file_change_log = create_log_tab(pc_tab_control, "File Changes Log")
        suspicious_log = create_log_tab(pc_tab_control, "Suspicious Activity Log")
        usb_log = create_log_tab(pc_tab_control, "USB Log")
        screenshot_canvas = create_screenshot_tab(pc_tab_control)
        pc_tabs[client_ip] = (window_log, keylog_log, process_log, file_change_log, suspicious_log, usb_log, screenshot_canvas)
    logs = pc_tabs[client_ip]
    window_log, keylog_log, process_log, file_change_log, suspicious_log, usb_log, screenshot_canvas = logs
    try:
        while server_running:
            header = b""
            while b"\n" not in header:
                chunk = client_socket.recv(1)
                if not chunk:
                    break
                header += chunk
            if not header:
                break
            header = header.decode().strip()
            print(f"Debug: Raw header from {client_ip}: {header}")
            logging.info(f"Received header from {client_ip}: {header}")
            try:
                data_type, data_length = header.split(":")
                data_length = int(data_length)
            except ValueError:
                logging.error(f"Invalid header format from {client_ip}: {header}")
                continue
            received_data = b""
            while len(received_data) < data_length:
                chunk = client_socket.recv(min(4096, data_length - len(received_data)))
                if not chunk:
                    break
                received_data += chunk
            print(f"Debug: Received {data_type} from {client_ip}, length: {len(received_data)}")
            logging.info(f"Received {data_type} of size {len(received_data)} bytes from {client_ip}")
            update_session_activity(client_ip)
            if data_type == "screenshot" or data_type == "suspicious_screenshot":
                try:
                    img = Image.open(io.BytesIO(received_data))
                    img.verify()
                    save_screenshot(client_ip, received_data, screenshot_canvas)
                except Exception as e:
                    logging.error(f"Invalid image data received from {client_ip}: {e}")
            elif data_type == "active_window":
                log_text_data(client_ip, "Window Activity", received_data.decode(), window_log)
            elif data_type == "keylogs":
                log_text_data(client_ip, "Keylogs", received_data.decode(), keylog_log)
            elif data_type == "processes":
                log_text_data(client_ip, "Processes", received_data.decode(), process_log)
            elif data_type == "file_changes":
                log_text_data(client_ip, "File Changes", received_data.decode(), file_change_log)
            elif data_type == "suspicious_log":
                log_suspicious_activity(client_ip, received_data.decode(), suspicious_log)
            elif data_type == "usb_log":
                decoded_data = received_data.decode()
                print(f"Debug: Processing usb_log from {client_ip}: {decoded_data}")
                log_text_data(client_ip, "USB Log", decoded_data, usb_log)
    except Exception as e:
        logging.error(f"Error handling client {client_ip}: {e}")
    finally:
        client_socket.close()
        end_session(client_ip)
        logging.info(f"Connection closed with {client_ip}")
        if not pc_tabs:
            placeholder_tab = ttk.Frame(main_tab_control)
            main_tab_control.add(placeholder_tab, text="PC Monitor")
            placeholder_label = tk.Label(placeholder_tab, text="No PCs connected yet", font=("Helvetica", 16), bg=PRIMARY_BG, fg=TEXT_COLOR)
            placeholder_label.pack(expand=True)

def start_admin_server(main_tab_control, start_button, stop_button):
    global server_running
    config = load_config()
    ADMIN_HOST = config["ADMIN_HOST"]
    ADMIN_PORT = config["ADMIN_PORT"]
    if not ADMIN_HOST or ADMIN_HOST.strip() == "":
        ADMIN_HOST = "127.0.0.1"
        logging.warning("Invalid ADMIN_HOST in config, falling back to 127.0.0.1")
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server_socket.bind((ADMIN_HOST, ADMIN_PORT))
    except (socket.gaierror, OSError) as e:
        logging.error(f"Failed to bind to {ADMIN_HOST}:{ADMIN_PORT}: {e}")
        messagebox.showerror("Error", f"Cannot bind to {ADMIN_HOST}:{ADMIN_PORT}. Check network settings or port availability.")
        return
    server_socket.listen(10)
    logging.info(f"Admin server started. Listening on {ADMIN_HOST}:{ADMIN_PORT}")
    def server_loop():
        nonlocal server_socket
        while server_running:
            try:
                client_socket, client_address = server_socket.accept()
                client_ip = client_address[0]
                logging.info(f"Connection established with {client_ip}")
                client_thread = threading.Thread(target=handle_client, args=(client_socket, client_ip, main_tab_control))
                client_thread.daemon = True
                client_thread.start()
            except Exception as e:
                if server_running:
                    logging.error(f"Error accepting connection: {e}")
        server_socket.close()
        logging.info("Admin server stopped.")
    start_button.config(state=tk.DISABLED)
    stop_button.config(state=tk.NORMAL)
    threading.Thread(target=server_loop, daemon=True).start()

def stop_admin_server(start_button, stop_button):
    global server_running
    server_running = False
    start_button.config(state=tk.NORMAL)
    stop_button.config(state=tk.DISABLED)
    logging.info("Admin server stopping.")

def start_target_server():
    config = load_config()
    TARGET_HOST = config["TARGET_HOST"]
    TARGET_PORT = config["TARGET_PORT"]
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((TARGET_HOST, TARGET_PORT))
        server_socket.listen(5)
        logging.info(f"Target server listening on {TARGET_HOST}:{TARGET_PORT}")
        while True:
            client_socket, client_address = server_socket.accept()
            logging.info(f"Accepted connection from {client_address}")
            try:
                header = b""
                while b"\n" not in header:
                    header += client_socket.recv(1)
                header = header.decode().strip()
                data_type, data_length = header.split(":")
                data_length = int(data_length)
                received_data = b""
                while len(received_data) < data_length:
                    chunk = client_socket.recv(min(4096, data_length - len(received_data)))
                    if not chunk:
                        break
                    received_data += chunk
                logging.info(f"Received {data_type} of size {len(received_data)} bytes")
                config = load_config()
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as admin_socket:
                    admin_socket.connect((config["ADMIN_HOST"], config["ADMIN_PORT"]))
                    admin_socket.sendall(f"{data_type}:{data_length}\n".encode() + received_data)
            except Exception as e:
                logging.error(f"Error receiving data: {e}")
            finally:
                client_socket.close()

if __name__ == "__main__":
    if not load_credentials():
        create_signup_window()
    else:
        create_login_window()
    target_server_thread = threading.Thread(target=start_target_server, daemon=True)
    target_server_thread.start()
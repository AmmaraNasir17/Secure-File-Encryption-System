from pathlib import Path
from shutil import copy2
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from crypto_text import TEXT_CRYPTO_METHODS, decrypt_text, encrypt_text
from database import DatabaseManager
from decrypt import decrypt_file
from encrypt import encrypt_file
from hashing import sha256_file
from login import LoginManager
from logs import SecurityAuditLogger
from signature import (
    default_private_key_path,
    default_public_key_path,
    generate_rsa_key_pair,
    sign_file,
    verify_signature,
)
from utils import (
    APP_TITLE,
    BACKUP_DIR,
    COLORS,
    KEY_DIR,
    center_window,
    format_bytes,
    open_folder,
    password_strength,
)


class SecureFileEncryptionApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.minsize(1080, 700)
        center_window(self, 1180, 760)

        self.database = DatabaseManager()
        self.audit_logger = SecurityAuditLogger(self.database)
        self.login_manager = LoginManager(self.database, self.audit_logger)
        self.current_user = ""
        self.dark_mode = False

        self.content = None
        self.nav_buttons = {}
        self.configure_styles()
        self.show_login()

    def palette(self):
        if not self.dark_mode:
            return COLORS
        return {
            **COLORS,
            "bg": "#0f172a",
            "panel": "#111827",
            "sidebar": "#020617",
            "sidebar_hover": "#1e293b",
            "text": "#f8fafc",
            "muted": "#cbd5e1",
            "border": "#334155",
            "soft": "#172554",
        }

    def configure_styles(self):
        colors = self.palette()
        self.configure(bg=colors["bg"])
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("App.TFrame", background=colors["bg"])
        style.configure("Card.TFrame", background=colors["panel"], relief="flat")
        style.configure("Sidebar.TFrame", background=colors["sidebar"])
        style.configure("Header.TFrame", background=colors["bg"])
        style.configure("TLabel", background=colors["bg"], foreground=colors["text"], font=("Segoe UI", 10))
        style.configure("Card.TLabel", background=colors["panel"], foreground=colors["text"], font=("Segoe UI", 10))
        style.configure("Title.TLabel", background=colors["bg"], foreground=colors["text"], font=("Segoe UI Semibold", 22))
        style.configure("Hero.TLabel", background=colors["bg"], foreground=colors["text"], font=("Segoe UI Semibold", 28))
        style.configure("Subtitle.TLabel", background=colors["bg"], foreground=colors["muted"], font=("Segoe UI", 11))
        style.configure("CardTitle.TLabel", background=colors["panel"], foreground=colors["text"], font=("Segoe UI Semibold", 13))
        style.configure("Muted.Card.TLabel", background=colors["panel"], foreground=colors["muted"], font=("Segoe UI", 9))
        style.configure("SidebarTitle.TLabel", background=colors["sidebar"], foreground="#ffffff", font=("Segoe UI Semibold", 14))
        style.configure("SidebarMuted.TLabel", background=colors["sidebar"], foreground="#98a2b3", font=("Segoe UI", 9))
        style.configure("TButton", font=("Segoe UI Semibold", 10), padding=(12, 8))
        style.configure("Primary.TButton", background=colors["primary"], foreground="#ffffff", bordercolor=colors["primary"])
        style.map("Primary.TButton", background=[("active", colors["primary_dark"])])
        style.configure("Secondary.TButton", background=colors["soft"], foreground=colors["primary"], bordercolor=colors["border"])
        style.configure("Danger.TButton", background="#fee4e2", foreground=colors["danger"], bordercolor="#fda29b")
        style.configure("Nav.TButton", background=colors["sidebar"], foreground="#ffffff", anchor="w", padding=(16, 10), borderwidth=0)
        style.map("Nav.TButton", background=[("active", colors["sidebar_hover"])])
        style.configure("Treeview", rowheight=28, font=("Segoe UI", 9))
        style.configure("Treeview.Heading", font=("Segoe UI Semibold", 9))
        style.configure("Horizontal.TProgressbar", troughcolor=colors["border"], background=colors["primary"])

    def clear_window(self):
        for widget in self.winfo_children():
            widget.destroy()

    def clear_content(self):
        if self.content is None:
            raise RuntimeError("Content frame is not ready.")
        for widget in self.content.winfo_children():
            widget.destroy()
        return self.content

    def show_login(self):
        self.clear_window()
        colors = self.palette()
        outer = ttk.Frame(self, style="App.TFrame", padding=40)
        outer.pack(fill="both", expand=True)
        outer.columnconfigure(0, weight=1)
        outer.rowconfigure(0, weight=1)

        card = ttk.Frame(outer, style="Card.TFrame", padding=34)
        card.grid(row=0, column=0, sticky="nsew")
        card.columnconfigure(0, weight=1)
        card.columnconfigure(1, weight=1)

        left = ttk.Frame(card, style="Card.TFrame", padding=(10, 10, 28, 10))
        left.grid(row=0, column=0, sticky="nsew")
        right = ttk.Frame(card, style="Card.TFrame", padding=(28, 10, 10, 10))
        right.grid(row=0, column=1, sticky="nsew")

        ttk.Label(left, text="Secure File Encryption", style="CardTitle.TLabel", font=("Segoe UI Semibold", 24)).pack(anchor="w")
        ttk.Label(
            left,
            text="Cryptography System",
            style="Muted.Card.TLabel",
            font=("Segoe UI Semibold", 18),
        ).pack(anchor="w", pady=(0, 18))
        ttk.Label(
            left,
            text=(
                "Muhammad Awais Riaz FA23-BCS-060 \n"
                "Ammar Rasool SP24-BDS-005 \n"
                "Ammara Nasir SP24-BDS-006 \n"
            ),
            style="Card.TLabel",
            wraplength=450,
            justify="left",
        ).pack(anchor="w", pady=(0, 24))

        for title, detail in (
            ("Text Cryptography", "Caesar, Vigenere, AES, DES, and Rail Fence"),
            ("File Encryption", "Password based AES file encryption and decryption"),
            ("Project Records", "Saved hashes, signatures, backups, and logs"),
        ):
            block = ttk.Frame(left, style="Card.TFrame")
            block.pack(fill="x", pady=7)
            ttk.Label(block, text=title, style="CardTitle.TLabel").pack(anchor="w")
            ttk.Label(block, text=detail, style="Muted.Card.TLabel", wraplength=420).pack(anchor="w")

        ttk.Label(right, text="Login / Register", style="CardTitle.TLabel", font=("Segoe UI Semibold", 18)).pack(anchor="w", pady=(0, 18))
        username_var = tk.StringVar()
        password_var = tk.StringVar()
        message_var = tk.StringVar(value="Create an account or log in to continue.")
        strength_var = tk.StringVar(value="Enter a password")

        self.form_label(right, "Username").pack(anchor="w")
        username_entry = ttk.Entry(right, textvariable=username_var, font=("Segoe UI", 11))
        username_entry.pack(fill="x", pady=(4, 14))

        self.form_label(right, "Password").pack(anchor="w")
        password_entry = ttk.Entry(right, textvariable=password_var, show="*", font=("Segoe UI", 11))
        password_entry.pack(fill="x", pady=(4, 4))
        strength_label = ttk.Label(right, textvariable=strength_var, style="Muted.Card.TLabel", wraplength=360)
        strength_label.pack(anchor="w", pady=(0, 14))

        def update_strength(*args):
            _, message = password_strength(password_var.get())
            strength_var.set(message)

        password_var.trace_add("write", update_strength)

        status_label = ttk.Label(right, textvariable=message_var, style="Muted.Card.TLabel", wraplength=370)
        status_label.pack(anchor="w", pady=(4, 18))

        button_row = ttk.Frame(right, style="Card.TFrame")
        button_row.pack(fill="x")

        def do_login():
            ok, message = self.login_manager.authenticate(username_var.get(), password_var.get())
            message_var.set(message)
            if ok:
                self.current_user = username_var.get().strip()
                self.show_main_layout()

        def do_register():
            ok, message = self.login_manager.register_user(username_var.get(), password_var.get())
            message_var.set(message)
            if ok:
                messagebox.showinfo("Registration", message)

        ttk.Button(button_row, text="Login", command=do_login, style="Primary.TButton").pack(side="left", padx=(0, 10))
        ttk.Button(button_row, text="Register", command=do_register, style="Secondary.TButton").pack(side="left")
        username_entry.focus_set()
        self.bind("<Return>", lambda event: do_login())

        ttk.Label(
            right,
            text="Password hashes are stored, not plaintext passwords.",
            style="Muted.Card.TLabel",
            wraplength=360,
        ).pack(anchor="w", pady=(28, 0))
        card.configure(style="Card.TFrame")
        outer.configure(style="App.TFrame")
        self.configure(bg=colors["bg"])

    def form_label(self, parent, text):
        return ttk.Label(parent, text=text, style="Card.TLabel", font=("Segoe UI Semibold", 10))

    def show_main_layout(self):
        self.clear_window()
        colors = self.palette()
        shell = ttk.Frame(self, style="App.TFrame")
        shell.pack(fill="both", expand=True)

        sidebar = ttk.Frame(shell, style="Sidebar.TFrame", width=240, padding=(12, 18))
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)

        ttk.Label(sidebar, text="Shield Suite", style="SidebarTitle.TLabel").pack(anchor="w", pady=(2, 2))
        ttk.Label(sidebar, text=f"Signed in: {self.current_user}", style="SidebarMuted.TLabel").pack(anchor="w", pady=(0, 18))

        nav_items = [
            ("Dashboard", self.render_dashboard),
            ("Cryptography", self.render_cryptography_page),
            ("Encrypt File", self.render_encrypt_page),
            ("Decrypt File", self.render_decrypt_page),
            ("Integrity", self.render_integrity_page),
            ("RSA Signatures", self.render_signature_page),
            ("Backups", self.render_backup_page),
            ("Security Logs", self.render_logs_page),
        ]
        self.nav_buttons.clear()
        for label, command in nav_items:
            button = ttk.Button(sidebar, text=label, command=command, style="Nav.TButton")
            button.pack(fill="x", pady=2)
            self.nav_buttons[label] = button

        bottom = ttk.Frame(sidebar, style="Sidebar.TFrame")
        bottom.pack(side="bottom", fill="x", pady=(18, 0))
        ttk.Button(bottom, text="Toggle Dark Mode", command=self.toggle_dark_mode, style="Nav.TButton").pack(fill="x", pady=2)
        ttk.Button(bottom, text="Logout", command=self.logout, style="Nav.TButton").pack(fill="x", pady=2)

        main_area = ttk.Frame(shell, style="App.TFrame", padding=(26, 20))
        main_area.pack(side="left", fill="both", expand=True)
        header = ttk.Frame(main_area, style="Header.TFrame")
        header.pack(fill="x", pady=(0, 10))
        ttk.Label(header, text=APP_TITLE, style="Subtitle.TLabel").pack(anchor="w")
        ttk.Label(header, text="Cryptography Lab", style="Title.TLabel").pack(anchor="w")
        self.content = ttk.Frame(main_area, style="App.TFrame")
        self.content.pack(fill="both", expand=True)
        self.configure(bg=colors["bg"])
        self.render_dashboard()

    def toggle_dark_mode(self):
        self.dark_mode = not self.dark_mode
        self.configure_styles()
        if self.current_user:
            self.show_main_layout()
        else:
            self.show_login()

    def logout(self):
        self.audit_logger.record(self.current_user, "USER_LOGOUT")
        self.current_user = ""
        self.show_login()

    def page_header(self, parent, title, subtitle):
        ttk.Label(parent, text=title, style="Hero.TLabel").pack(anchor="w")
        ttk.Label(parent, text=subtitle, style="Subtitle.TLabel", wraplength=880).pack(anchor="w", pady=(2, 18))

    def make_card(self, parent, padding=18):
        card = ttk.Frame(parent, style="Card.TFrame", padding=padding)
        return card

    def browse_file(self, variable, filetypes=None):
        path = filedialog.askopenfilename(filetypes=filetypes or [("All files", "*.*")])
        if path:
            variable.set(path)

    def browse_folder(self, variable):
        path = filedialog.askdirectory()
        if path:
            variable.set(path)

    def append_text(self, widget, lines):
        widget.configure(state="normal")
        if isinstance(lines, str):
            widget.insert("end", lines + "\n")
        else:
            widget.insert("end", "\n".join(lines) + "\n")
        widget.see("end")
        widget.configure(state="disabled")

    def make_output_box(self, parent, height=8):
        colors = self.palette()
        output = tk.Text(
            parent,
            height=height,
            wrap="word",
            bg=colors["panel"],
            fg=colors["text"],
            insertbackground=colors["text"],
            relief="solid",
            bd=1,
            font=("Consolas", 9),
        )
        output.configure(state="disabled")
        return output

    def render_dashboard(self) -> None:
        parent = self.clear_content()
        self.page_header(parent, "Dashboard", "Overview of authentication, file tools, text cryptography, logs, and backups.")

        stats = ttk.Frame(parent, style="App.TFrame")
        stats.pack(fill="x", pady=(0, 14))
        values = [
            ("Users", self.database.count_rows("users")),
            ("Security Logs", self.database.count_rows("logs")),
            ("Integrity Records", self.database.count_rows("integrity")),
            ("Backup Files", len([item for item in BACKUP_DIR.iterdir() if item.is_file()])),
        ]
        for title, value in values:
            card = self.make_card(stats)
            card.pack(side="left", fill="both", expand=True, padx=(0, 12))
            ttk.Label(card, text=str(value), style="CardTitle.TLabel", font=("Segoe UI Semibold", 24)).pack(anchor="w")
            ttk.Label(card, text=title, style="Muted.Card.TLabel").pack(anchor="w")

        grid = ttk.Frame(parent, style="App.TFrame")
        grid.pack(fill="both", expand=True)
        grid.columnconfigure(0, weight=1)
        grid.columnconfigure(1, weight=1)

        modules = [
            ("AES-256 File Protection", "Encrypt any binary file using password-derived AES-256-GCM keys with random salt and nonce."),
            ("Text Cryptography", "Try Caesar, Vigenere, AES, DES, and Rail Fence from one page."),
            ("SHA-256 Integrity", "Generate hashes before encryption and compare after decryption to detect tampering."),
            ("RSA Digital Signatures", "Generate key pairs, sign encrypted files, and verify authenticity with public keys."),
            ("Security Logging", "Every login, encryption, decryption, and failed access event is stored for auditing."),
            ("Backup Recovery", "Original files are backed up before encryption and can be restored later."),
        ]
        for index, (title, detail) in enumerate(modules):
            card = self.make_card(grid)
            card.grid(row=index // 2, column=index % 2, sticky="nsew", padx=8, pady=8)
            ttk.Label(card, text=title, style="CardTitle.TLabel").pack(anchor="w")
            ttk.Label(card, text=detail, style="Muted.Card.TLabel", wraplength=390).pack(anchor="w", pady=(6, 0))

    def render_cryptography_page(self) -> None:
        parent = self.clear_content()
        self.page_header(parent, "Cryptography", "Encrypt and decrypt plain text with common course algorithms.")

        card = self.make_card(parent)
        card.pack(fill="x")

        top = ttk.Frame(card, style="Card.TFrame")
        top.pack(fill="x", pady=(0, 12))

        method_var = tk.StringVar(value=TEXT_CRYPTO_METHODS[0])
        key_var = tk.StringVar(value="3")
        hint_var = tk.StringVar()

        self.form_label(top, "Encryption type").grid(row=0, column=0, sticky="w", padx=(0, 12))
        self.form_label(top, "Key / password / number").grid(row=0, column=1, sticky="w")

        method_box = ttk.Combobox(top, textvariable=method_var, values=TEXT_CRYPTO_METHODS, state="readonly", width=24)
        method_box.grid(row=1, column=0, sticky="ew", padx=(0, 12), pady=(4, 0))
        key_entry = ttk.Entry(top, textvariable=key_var)
        key_entry.grid(row=1, column=1, sticky="ew", pady=(4, 0))
        top.columnconfigure(0, weight=1)
        top.columnconfigure(1, weight=2)

        ttk.Label(card, textvariable=hint_var, style="Muted.Card.TLabel", wraplength=860).pack(anchor="w", pady=(0, 10))

        text_row = ttk.Frame(card, style="Card.TFrame")
        text_row.pack(fill="both", expand=True)
        text_row.columnconfigure(0, weight=1)
        text_row.columnconfigure(1, weight=1)

        left = ttk.Frame(text_row, style="Card.TFrame")
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        right = ttk.Frame(text_row, style="Card.TFrame")
        right.grid(row=0, column=1, sticky="nsew", padx=(8, 0))

        self.form_label(left, "Plain text / cipher text").pack(anchor="w")
        input_text = tk.Text(left, height=12, wrap="word", font=("Consolas", 10), relief="solid", bd=1)
        input_text.pack(fill="both", expand=True, pady=(4, 0))

        self.form_label(right, "Result").pack(anchor="w")
        result_text = self.make_output_box(right, height=12)
        result_text.pack(fill="both", expand=True, pady=(4, 0))

        def set_result(value: str) -> None:
            result_text.configure(state="normal")
            result_text.delete("1.0", "end")
            result_text.insert("1.0", value)
            result_text.configure(state="disabled")

        def get_input() -> str:
            return input_text.get("1.0", "end-1c")

        def change_hint(*_: object) -> None:
            method = method_var.get()
            hints = {
                "Caesar": ("3", "Caesar uses a number shift. Empty key means 3."),
                "Vigenere": ("security", "Vigenere uses a word key."),
                "AES": ("mypassword", "AES uses a password and returns a JSON cipher package."),
                "DES": ("mypassword", "DES uses a password and returns a JSON cipher package."),
                "Rail Fence": ("3", "Rail Fence uses the number of rails. Empty key means 3."),
            }
            default_key, hint = hints[method]
            if not key_var.get().strip():
                key_var.set(default_key)
            hint_var.set(hint)

        def run_encrypt() -> None:
            try:
                value = encrypt_text(method_var.get(), get_input(), key_var.get())
                set_result(value)
                self.audit_logger.record(self.current_user, f"TEXT_ENCRYPT_{method_var.get().upper().replace(' ', '_')}")
            except Exception as exc:
                messagebox.showerror("Cryptography", str(exc))

        def run_decrypt() -> None:
            try:
                value = decrypt_text(method_var.get(), get_input(), key_var.get())
                set_result(value)
                self.audit_logger.record(self.current_user, f"TEXT_DECRYPT_{method_var.get().upper().replace(' ', '_')}")
            except Exception as exc:
                messagebox.showerror("Cryptography", str(exc))

        def use_result_as_input() -> None:
            text = result_text.get("1.0", "end-1c")
            input_text.delete("1.0", "end")
            input_text.insert("1.0", text)

        def clear_text() -> None:
            input_text.delete("1.0", "end")
            set_result("")

        buttons = ttk.Frame(card, style="Card.TFrame")
        buttons.pack(anchor="e", pady=(12, 0))
        ttk.Button(buttons, text="Encrypt", command=run_encrypt, style="Primary.TButton").pack(side="left", padx=(0, 8))
        ttk.Button(buttons, text="Decrypt", command=run_decrypt, style="Secondary.TButton").pack(side="left", padx=(0, 8))
        ttk.Button(buttons, text="Use Result", command=use_result_as_input, style="Secondary.TButton").pack(side="left", padx=(0, 8))
        ttk.Button(buttons, text="Clear", command=clear_text, style="Secondary.TButton").pack(side="left")

        method_var.trace_add("write", change_hint)
        change_hint()

    def render_encrypt_page(self) -> None:
        parent = self.clear_content()
        self.page_header(parent, "Encrypt File", "Protect files with AES-256-GCM, store SHA-256 integrity data, and optionally sign encrypted output with RSA.")

        card = self.make_card(parent)
        card.pack(fill="x")
        file_var = tk.StringVar()
        password_var = tk.StringVar()
        private_key_var = tk.StringVar(value=str(default_private_key_path(self.current_user)) if default_private_key_path(self.current_user).exists() else "")
        sign_var = tk.BooleanVar(value=bool(private_key_var.get()))

        self.form_label(card, "File to encrypt").pack(anchor="w")
        row = ttk.Frame(card, style="Card.TFrame")
        row.pack(fill="x", pady=(4, 12))
        ttk.Entry(row, textvariable=file_var).pack(side="left", fill="x", expand=True)
        ttk.Button(row, text="Browse", command=lambda: self.browse_file(file_var)).pack(side="left", padx=(8, 0))

        self.form_label(card, "Encryption password").pack(anchor="w")
        ttk.Entry(card, textvariable=password_var, show="*").pack(fill="x", pady=(4, 12))

        ttk.Checkbutton(card, text="Sign encrypted file with RSA private key", variable=sign_var).pack(anchor="w", pady=(0, 8))
        key_row = ttk.Frame(card, style="Card.TFrame")
        key_row.pack(fill="x", pady=(0, 12))
        ttk.Entry(key_row, textvariable=private_key_var).pack(side="left", fill="x", expand=True)
        ttk.Button(key_row, text="Private Key", command=lambda: self.browse_file(private_key_var, [("PEM keys", "*.pem"), ("All files", "*.*")])).pack(side="left", padx=(8, 0))
        ttk.Button(key_row, text="Generate Keys", command=self.generate_keys_for_current_user).pack(side="left", padx=(8, 0))

        progress = ttk.Progressbar(card, mode="indeterminate")
        progress.pack(fill="x", pady=(0, 12))
        output = self.make_output_box(parent, height=9)
        output.pack(fill="both", expand=True, pady=(14, 0))

        def do_encrypt() -> None:
            try:
                progress.start(12)
                self.update_idletasks()
                result = encrypt_file(
                    file_var.get(),
                    password_var.get(),
                    self.current_user,
                    self.database,
                    self.audit_logger,
                    sign_output=sign_var.get(),
                    private_key_path=private_key_var.get() or None,
                )
                lines = [
                    "Encryption successful.",
                    f"Encrypted file: {result['encrypted_path']}",
                    f"Backup copy: {result['backup_path']}",
                    f"SHA-256 hash: {result['hash']}",
                    f"Original size: {result['size']}",
                ]
                if result["signature_path"]:
                    lines.append(f"RSA signature: {result['signature_path']}")
                self.append_text(output, lines)
                messagebox.showinfo("Encryption", "File encrypted successfully.")
            except Exception as exc:
                self.audit_logger.record(self.current_user, "ENCRYPTION_FAILED", file_var.get())
                messagebox.showerror("Encryption Error", str(exc))
            finally:
                progress.stop()

        ttk.Button(card, text="Encrypt Securely", command=do_encrypt, style="Primary.TButton").pack(anchor="e")

    def generate_keys_for_current_user(self) -> tuple[Path, Path]:
        private_path, public_path = generate_rsa_key_pair(self.current_user)
        self.audit_logger.record(self.current_user, "RSA_KEY_PAIR_GENERATED", str(KEY_DIR))
        messagebox.showinfo("RSA Keys", f"Keys generated:\n\nPrivate: {private_path}\nPublic: {public_path}")
        return private_path, public_path

    def render_decrypt_page(self) -> None:
        parent = self.clear_content()
        self.page_header(parent, "Decrypt File", "Restore encrypted files, validate AES-GCM authentication, compare SHA-256 hashes, and verify RSA signatures.")

        card = self.make_card(parent)
        card.pack(fill="x")
        file_var = tk.StringVar()
        password_var = tk.StringVar()
        output_folder_var = tk.StringVar()
        public_key_var = tk.StringVar(value=str(default_public_key_path(self.current_user)) if default_public_key_path(self.current_user).exists() else "")
        signature_var = tk.StringVar()
        verify_signature_var = tk.BooleanVar(value=bool(public_key_var.get()))

        self.form_label(card, "Encrypted file").pack(anchor="w")
        row = ttk.Frame(card, style="Card.TFrame")
        row.pack(fill="x", pady=(4, 12))
        ttk.Entry(row, textvariable=file_var).pack(side="left", fill="x", expand=True)
        ttk.Button(row, text="Browse", command=lambda: self.browse_file(file_var, [("Encrypted files", "*.enc"), ("All files", "*.*")])).pack(side="left", padx=(8, 0))

        self.form_label(card, "Decryption password").pack(anchor="w")
        ttk.Entry(card, textvariable=password_var, show="*").pack(fill="x", pady=(4, 12))

        self.form_label(card, "Output folder").pack(anchor="w")
        folder_row = ttk.Frame(card, style="Card.TFrame")
        folder_row.pack(fill="x", pady=(4, 12))
        ttk.Entry(folder_row, textvariable=output_folder_var).pack(side="left", fill="x", expand=True)
        ttk.Button(folder_row, text="Folder", command=lambda: self.browse_folder(output_folder_var)).pack(side="left", padx=(8, 0))

        ttk.Checkbutton(card, text="Verify RSA signature during decryption", variable=verify_signature_var).pack(anchor="w", pady=(0, 8))
        key_row = ttk.Frame(card, style="Card.TFrame")
        key_row.pack(fill="x", pady=(0, 8))
        ttk.Entry(key_row, textvariable=public_key_var).pack(side="left", fill="x", expand=True)
        ttk.Button(key_row, text="Public Key", command=lambda: self.browse_file(public_key_var, [("PEM keys", "*.pem"), ("All files", "*.*")])).pack(side="left", padx=(8, 0))

        sig_row = ttk.Frame(card, style="Card.TFrame")
        sig_row.pack(fill="x", pady=(0, 12))
        ttk.Entry(sig_row, textvariable=signature_var).pack(side="left", fill="x", expand=True)
        ttk.Button(sig_row, text="Signature", command=lambda: self.browse_file(signature_var, [("Signature", "*.sig"), ("All files", "*.*")])).pack(side="left", padx=(8, 0))

        progress = ttk.Progressbar(card, mode="indeterminate")
        progress.pack(fill="x", pady=(0, 12))
        output = self.make_output_box(parent, height=10)
        output.pack(fill="both", expand=True, pady=(14, 0))

        def do_decrypt() -> None:
            try:
                progress.start(12)
                self.update_idletasks()
                result = decrypt_file(
                    file_var.get(),
                    password_var.get(),
                    self.current_user,
                    self.database,
                    self.audit_logger,
                    output_folder=output_folder_var.get() or None,
                    verify_signature_flag=verify_signature_var.get(),
                    public_key_path=public_key_var.get() or None,
                    signature_path=signature_var.get() or None,
                )
                lines = [
                    "Decryption completed.",
                    f"Output file: {result['output_path']}",
                    result["integrity_message"],
                    f"Expected hash: {result['expected_hash']}",
                    f"Actual hash:   {result['actual_hash']}",
                    result["signature_message"],
                ]
                self.append_text(output, lines)
                if result["integrity_ok"]:
                    messagebox.showinfo("Decryption", "File decrypted and integrity verified.")
                else:
                    messagebox.showwarning("Integrity Warning", "File integrity compromised.")
            except Exception as exc:
                messagebox.showerror("Decryption Error", str(exc))
            finally:
                progress.stop()

        ttk.Button(card, text="Decrypt and Verify", command=do_decrypt, style="Primary.TButton").pack(anchor="e")

    def render_integrity_page(self) -> None:
        parent = self.clear_content()
        self.page_header(parent, "Integrity Verification", "Generate SHA-256 hashes and compare files with stored integrity records.")

        card = self.make_card(parent)
        card.pack(fill="x")
        file_var = tk.StringVar()
        self.form_label(card, "File").pack(anchor="w")
        row = ttk.Frame(card, style="Card.TFrame")
        row.pack(fill="x", pady=(4, 12))
        ttk.Entry(row, textvariable=file_var).pack(side="left", fill="x", expand=True)
        ttk.Button(row, text="Browse", command=lambda: self.browse_file(file_var)).pack(side="left", padx=(8, 0))

        output = self.make_output_box(parent, height=14)
        output.pack(fill="both", expand=True, pady=(14, 0))

        def generate_hash() -> None:
            try:
                digest = sha256_file(file_var.get())
                size = format_bytes(Path(file_var.get()).stat().st_size)
                self.audit_logger.record(self.current_user, "SHA256_HASH_GENERATED", file_var.get())
                self.append_text(output, [f"File: {file_var.get()}", f"Size: {size}", f"SHA-256: {digest}"])
            except Exception as exc:
                messagebox.showerror("Hash Error", str(exc))

        def verify_stored() -> None:
            try:
                path = Path(file_var.get())
                digest = sha256_file(path)
                record = self.database.get_integrity_by_original_file(path) or self.database.get_integrity_by_encrypted_file(path)
                if not record:
                    self.append_text(output, "No stored integrity record found for this file.")
                    return
                status = "MATCH - integrity preserved" if digest == record["hash_value"] else "MISMATCH - file integrity compromised"
                self.audit_logger.record(self.current_user, "INTEGRITY_RECORD_CHECKED", file_var.get())
                self.append_text(
                    output,
                    [
                        f"Stored record: {record['filename']}",
                        f"Stored hash:  {record['hash_value']}",
                        f"Current hash: {digest}",
                        f"Result: {status}",
                    ],
                )
            except Exception as exc:
                messagebox.showerror("Integrity Error", str(exc))

        buttons = ttk.Frame(card, style="Card.TFrame")
        buttons.pack(anchor="e")
        ttk.Button(buttons, text="Generate SHA-256", command=generate_hash, style="Secondary.TButton").pack(side="left", padx=(0, 8))
        ttk.Button(buttons, text="Check Stored Record", command=verify_stored, style="Primary.TButton").pack(side="left")

    def render_signature_page(self) -> None:
        parent = self.clear_content()
        self.page_header(parent, "RSA Digital Signatures", "Generate RSA keys, sign encrypted files, and verify authenticity/non-repudiation.")

        card = self.make_card(parent)
        card.pack(fill="x")
        file_var = tk.StringVar()
        private_var = tk.StringVar(value=str(default_private_key_path(self.current_user)) if default_private_key_path(self.current_user).exists() else "")
        public_var = tk.StringVar(value=str(default_public_key_path(self.current_user)) if default_public_key_path(self.current_user).exists() else "")
        signature_var = tk.StringVar()

        self.form_label(card, "File to sign or verify").pack(anchor="w")
        file_row = ttk.Frame(card, style="Card.TFrame")
        file_row.pack(fill="x", pady=(4, 10))
        ttk.Entry(file_row, textvariable=file_var).pack(side="left", fill="x", expand=True)
        ttk.Button(file_row, text="File", command=lambda: self.browse_file(file_var)).pack(side="left", padx=(8, 0))

        self.form_label(card, "Private key for signing").pack(anchor="w")
        private_row = ttk.Frame(card, style="Card.TFrame")
        private_row.pack(fill="x", pady=(4, 10))
        ttk.Entry(private_row, textvariable=private_var).pack(side="left", fill="x", expand=True)
        ttk.Button(private_row, text="Private Key", command=lambda: self.browse_file(private_var, [("PEM keys", "*.pem"), ("All files", "*.*")])).pack(side="left", padx=(8, 0))

        self.form_label(card, "Public key for verification").pack(anchor="w")
        public_row = ttk.Frame(card, style="Card.TFrame")
        public_row.pack(fill="x", pady=(4, 10))
        ttk.Entry(public_row, textvariable=public_var).pack(side="left", fill="x", expand=True)
        ttk.Button(public_row, text="Public Key", command=lambda: self.browse_file(public_var, [("PEM keys", "*.pem"), ("All files", "*.*")])).pack(side="left", padx=(8, 0))

        self.form_label(card, "Signature file").pack(anchor="w")
        sig_row = ttk.Frame(card, style="Card.TFrame")
        sig_row.pack(fill="x", pady=(4, 12))
        ttk.Entry(sig_row, textvariable=signature_var).pack(side="left", fill="x", expand=True)
        ttk.Button(sig_row, text="Signature", command=lambda: self.browse_file(signature_var, [("Signature", "*.sig"), ("All files", "*.*")])).pack(side="left", padx=(8, 0))

        output = self.make_output_box(parent, height=10)
        output.pack(fill="both", expand=True, pady=(14, 0))

        def make_keys() -> None:
            private_path, public_path = self.generate_keys_for_current_user()
            private_var.set(str(private_path))
            public_var.set(str(public_path))
            self.append_text(output, [f"Private key: {private_path}", f"Public key: {public_path}"])

        def sign_selected() -> None:
            try:
                sig_path = sign_file(file_var.get(), private_var.get())
                signature_var.set(str(sig_path))
                self.audit_logger.record(self.current_user, "MANUAL_FILE_SIGNATURE_CREATED", file_var.get())
                self.append_text(output, f"Signature created: {sig_path}")
            except Exception as exc:
                messagebox.showerror("Signature Error", str(exc))

        def verify_selected() -> None:
            ok, message = verify_signature(file_var.get(), signature_var.get(), public_var.get())
            self.audit_logger.record(self.current_user, "MANUAL_FILE_SIGNATURE_VERIFIED", file_var.get())
            self.append_text(output, message)
            if ok:
                messagebox.showinfo("Signature", message)
            else:
                messagebox.showwarning("Signature", message)

        button_row = ttk.Frame(card, style="Card.TFrame")
        button_row.pack(anchor="e")
        ttk.Button(button_row, text="Generate Key Pair", command=make_keys, style="Secondary.TButton").pack(side="left", padx=(0, 8))
        ttk.Button(button_row, text="Sign File", command=sign_selected, style="Secondary.TButton").pack(side="left", padx=(0, 8))
        ttk.Button(button_row, text="Verify Signature", command=verify_selected, style="Primary.TButton").pack(side="left")

    def render_backup_page(self) -> None:
        parent = self.clear_content()
        self.page_header(parent, "Backup Recovery", "Recover secure backup copies created before encryption to support availability.")

        card = self.make_card(parent)
        card.pack(fill="both", expand=True)
        tree = ttk.Treeview(card, columns=("name", "size", "modified"), show="headings", height=13)
        tree.heading("name", text="Backup File")
        tree.heading("size", text="Size")
        tree.heading("modified", text="Modified")
        tree.column("name", width=520)
        tree.column("size", width=110)
        tree.column("modified", width=170)
        tree.pack(fill="both", expand=True)

        def refresh() -> None:
            for item in tree.get_children():
                tree.delete(item)
            for path in sorted(BACKUP_DIR.iterdir(), key=lambda item: item.stat().st_mtime, reverse=True):
                if path.is_file():
                    tree.insert("", "end", iid=str(path), values=(path.name, format_bytes(path.stat().st_size), path.stat().st_mtime))

        def restore_selected() -> None:
            selected = tree.selection()
            if not selected:
                messagebox.showwarning("Backup", "Select a backup file first.")
                return
            destination = filedialog.askdirectory(title="Choose restore folder")
            if not destination:
                return
            source = Path(selected[0])
            restored = Path(destination) / source.name
            copy2(source, restored)
            self.audit_logger.record(self.current_user, "BACKUP_RESTORED", str(restored))
            messagebox.showinfo("Backup", f"Backup restored:\n{restored}")

        buttons = ttk.Frame(card, style="Card.TFrame")
        buttons.pack(anchor="e", pady=(12, 0))
        ttk.Button(buttons, text="Refresh", command=refresh, style="Secondary.TButton").pack(side="left", padx=(0, 8))
        ttk.Button(buttons, text="Open Backup Folder", command=lambda: open_folder(BACKUP_DIR), style="Secondary.TButton").pack(side="left", padx=(0, 8))
        ttk.Button(buttons, text="Restore Selected", command=restore_selected, style="Primary.TButton").pack(side="left")
        refresh()

    def render_logs_page(self) -> None:
        parent = self.clear_content()
        self.page_header(parent, "Security Logs", "Audit trail for authentication, encryption, decryption, failed access, integrity failures, and suspicious activity.")

        card = self.make_card(parent)
        card.pack(fill="both", expand=True)
        tree = ttk.Treeview(card, columns=("id", "time", "user", "action", "file"), show="headings", height=18)
        for column, title, width in (
            ("id", "ID", 60),
            ("time", "Timestamp", 160),
            ("user", "User", 120),
            ("action", "Action", 240),
            ("file", "Filename", 410),
        ):
            tree.heading(column, text=title)
            tree.column(column, width=width)
        tree.pack(fill="both", expand=True)

        def refresh() -> None:
            for item in tree.get_children():
                tree.delete(item)
            for row in self.database.get_logs():
                tree.insert("", "end", values=(row["id"], row["timestamp"], row["username"], row["action"], row["filename"]))

        ttk.Button(card, text="Refresh Logs", command=refresh, style="Primary.TButton").pack(anchor="e", pady=(12, 0))
        refresh()

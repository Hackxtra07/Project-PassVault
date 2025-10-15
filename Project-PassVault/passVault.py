#!/usr/bin/env python3
"""
passVault.py — Advanced Password Manager (Tkinter + SQLite single-file)
Saves data to vault.db in the same folder as this script.
"""

import os
import json
import time
import threading
import base64
import secrets
import sqlite3
from datetime import datetime, timedelta
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

# Crypto libs
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet, InvalidToken
import bcrypt
import pyperclip
import string

# ----------------------------- CONFIG -----------------------------
DB_FILE = "vault.db"

AUTO_CLEAR_SECONDS = 15          # clipboard clear seconds
AUTO_LOCK_MINUTES = 5           # lock app after inactivity
PBKDF2_ITERATIONS = 200_000     # key derivation iterations
SALT_BYTES = 16                 # salt bytes to store per user

# ----------------------------- DB SETUP -----------------------------
def get_connection():
    conn = sqlite3.connect(DB_FILE, detect_types=sqlite3.PARSE_DECLTYPES|sqlite3.PARSE_COLNAMES)
    conn.row_factory = sqlite3.Row
    # enforce foreign keys
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def initialize_database():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash BLOB NOT NULL,
        salt BLOB NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS credentials (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        username TEXT,
        password_blob BLOB NOT NULL,
        notes TEXT,
        category TEXT,
        tags TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_used TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
    """)
    conn.commit()
    conn.close()

# ----------------------------- CRYPTO HELPERS -----------------------------
def derive_key(master_password: str, salt: bytes, iterations=PBKDF2_ITERATIONS) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    return key

def encrypt_blob(fernet: Fernet, plaintext: str) -> bytes:
    return fernet.encrypt(plaintext.encode())

def decrypt_blob(fernet: Fernet, blob: bytes) -> str:
    return fernet.decrypt(blob).decode()

def hash_master_password(password: str) -> bytes:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

def check_master_password(password: str, pw_hash: bytes) -> bool:
    return bcrypt.checkpw(password.encode(), pw_hash)

# ----------------------------- UTILITIES -----------------------------
def generate_password(length=16, use_upper=True, use_lower=True, use_digits=True, use_symbols=True):
    pool = ""
    if use_upper: pool += string.ascii_uppercase
    if use_lower: pool += string.ascii_lowercase
    if use_digits: pool += string.digits
    if use_symbols: pool += "!@#$%^&*()-_=+[]{};:,.<>?/"
    if not pool:
        pool = string.ascii_letters + string.digits
    return ''.join(secrets.choice(pool) for _ in range(length))

def password_strength(password: str):
    score = 0
    if len(password) >= 8: score += 1
    if len(password) >= 12: score += 1
    if any(c.islower() for c in password): score += 1
    if any(c.isupper() for c in password): score += 1
    if any(c.isdigit() for c in password): score += 1
    if any(c in "!@#$%^&*()-_=+[]{};:,.<>?/" for c in password): score += 1
    return min(score, 6)

# ----------------------------- APP CLASS -----------------------------
class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Advanced Password Manager")
        self.root.geometry("1000x700")
        self.theme = tk.StringVar(value="light")
        self.user = None
        self.fernet = None
        self.salt = None
        self.last_activity = datetime.now()
        self.auto_lock_after = timedelta(minutes=AUTO_LOCK_MINUTES)

        self.setup_ui()
        initialize_database()

        self._running = True
        self.root.after(1000, self.check_inactivity)

    # ---------------- UI ----------------
    def setup_ui(self):
        self.top_frame = tk.Frame(self.root)
        self.top_frame.pack(fill='x', padx=10, pady=6)

        tk.Label(self.top_frame, text="🔐 Advanced Password Manager", font=("Helvetica", 16, "bold")).pack(side='left')
        tk.Button(self.top_frame, text="Theme", command=self.toggle_theme).pack(side='right', padx=4)
        tk.Button(self.top_frame, text="Export", command=self.export_encrypted).pack(side='right', padx=4)
        tk.Button(self.top_frame, text="Import", command=self.import_encrypted).pack(side='right', padx=4)

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)

        self.login_tab = tk.Frame(self.notebook)
        self.app_tab = tk.Frame(self.notebook)

        self.notebook.add(self.login_tab, text="Login / Setup")
        self.notebook.add(self.app_tab, text="Vault")
        self.notebook.tab(1, state='disabled')

        self.build_login_tab()
        self.build_app_tab()
        self.apply_theme()

    def build_login_tab(self):
        frame = self.login_tab
        for widget in frame.winfo_children():
            widget.destroy()

        row = tk.Frame(frame)
        row.pack(padx=20, pady=20)

        tk.Label(row, text="Username:").grid(row=0, column=0, sticky='e')
        self.login_username = tk.Entry(row)
        self.login_username.grid(row=0, column=1, padx=6, pady=6)

        tk.Label(row, text="Master Password:").grid(row=1, column=0, sticky='e')
        self.login_password = tk.Entry(row, show="*")
        self.login_password.grid(row=1, column=1, padx=6, pady=6)

        btn_frame = tk.Frame(frame)
        btn_frame.pack(padx=20, pady=10)

        tk.Button(btn_frame, text="Login", command=self.login).pack(side='left', padx=6)
        tk.Button(btn_frame, text="Create Account", command=self.create_account_prompt).pack(side='left', padx=6)

    def build_app_tab(self):
        frame = self.app_tab
        for widget in frame.winfo_children():
            widget.destroy()

        tool = tk.Frame(frame)
        tool.pack(fill='x', padx=8, pady=8)

        tk.Label(tool, text="Search:").pack(side='left')
        self.search_var = tk.StringVar()
        tk.Entry(tool, textvariable=self.search_var).pack(side='left', padx=6)
        tk.Button(tool, text="Go", command=self.load_credentials).pack(side='left', padx=6)
        tk.Button(tool, text="Clear", command=self.clear_search).pack(side='left', padx=6)

        tk.Button(tool, text="Add Credential", command=self.open_add_window, bg="#4CAF50", fg="white").pack(side='right')

        cols = ("id", "title", "username", "category", "tags", "updated_at")
        self.tree = ttk.Treeview(frame, columns=cols, show='headings', selectmode='browse')
        for c in cols:
            self.tree.heading(c, text=c.title())
        self.tree.pack(fill='both', expand=True, padx=8, pady=8)
        self.tree.bind("<<TreeviewSelect>>", self.on_select_credential)

        act = tk.Frame(frame)
        act.pack(fill='x', padx=8, pady=6)
        tk.Button(act, text="View / Edit", command=self.open_edit_window).pack(side='left', padx=6)
        tk.Button(act, text="Copy Password", command=self.copy_password_to_clipboard).pack(side='left', padx=6)
        tk.Button(act, text="Delete", command=self.delete_selected).pack(side='left', padx=6)
        tk.Button(act, text="Audit", command=self.show_audit).pack(side='left', padx=6)

        details = tk.Frame(frame, bd=1, relief='sunken')
        details.pack(fill='x', padx=8, pady=6)
        self.detail_text = tk.Text(details, height=6)
        self.detail_text.pack(fill='x')

    def apply_theme(self):
        t = self.theme.get()
        bg = "#ffffff" if t == "light" else "#2b2b2b"
        self.root.configure(bg=bg)

    def toggle_theme(self):
        self.theme.set("dark" if self.theme.get() == "light" else "light")
        self.apply_theme()

    # ---------------- Account and login ----------------
    def create_account_prompt(self):
        win = tk.Toplevel(self.root)
        win.title("Create Account")
        tk.Label(win, text="Username").grid(row=0, column=0)
        uname = tk.Entry(win); uname.grid(row=0,column=1)
        tk.Label(win, text="Master Password").grid(row=1, column=0)
        pw = tk.Entry(win, show="*"); pw.grid(row=1,column=1)
        tk.Label(win, text="Confirm").grid(row=2, column=0)
        pw2 = tk.Entry(win, show="*"); pw2.grid(row=2,column=1)

        def create():
            username = uname.get().strip()
            p1 = pw.get().strip()
            p2 = pw2.get().strip()
            if not username or not p1:
                messagebox.showerror("Error", "Enter username and password")
                return
            if p1 != p2:
                messagebox.showerror("Error", "Passwords do not match")
                return
            salt = os.urandom(SALT_BYTES)
            pw_hash = hash_master_password(p1)
            try:
                conn = get_connection()
                cur = conn.cursor()
                cur.execute("INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)", (username, pw_hash, salt))
                conn.commit()
                conn.close()
                messagebox.showinfo("Success", "Account created. Please login.")
                win.destroy()
            except sqlite3.IntegrityError:
                messagebox.showerror("Error", "Username already exists.")

        tk.Button(win, text="Create", command=create).grid(row=3, column=0, columnspan=2, pady=8)

    def login(self):
        username = self.login_username.get().strip()
        pw = self.login_password.get().strip()
        if not username or not pw:
            messagebox.showerror("Error", "Enter username and password")
            return
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT id,password_hash,salt FROM users WHERE username=?", (username,))
        row = cur.fetchone()
        conn.close()
        if not row:
            messagebox.showerror("Error", "User not found")
            return
        user_id = row["id"]
        pw_hash = row["password_hash"]
        salt = row["salt"]
        if not check_master_password(pw, pw_hash):
            messagebox.showerror("Error", "Incorrect password")
            return
        self.user = {"id": user_id, "username": username}
        self.salt = salt
        key = derive_key(pw, salt)
        self.fernet = Fernet(key)
        self.notebook.tab(1, state='normal')
        self.notebook.select(1)
        self.load_credentials()
        self.last_activity = datetime.now()
        messagebox.showinfo("Welcome", f"Logged in as {username}")

    # ---------------- Credential CRUD ----------------
    def clear_search(self):
        self.search_var.set("")
        self.load_credentials()

    def load_credentials(self):
        if not self.user: return
        q = self.search_var.get().strip()
        conn = get_connection()
        cur = conn.cursor()
        if q:
            qlike = f"%{q}%"
            cur.execute("""SELECT id,title,username,category,tags,updated_at 
                           FROM credentials 
                           WHERE user_id=? AND (title LIKE ? OR username LIKE ? OR category LIKE ? OR tags LIKE ?) 
                           ORDER BY updated_at DESC""", (self.user['id'], qlike, qlike, qlike, qlike))
        else:
            cur.execute("SELECT id,title,username,category,tags,updated_at FROM credentials WHERE user_id=? ORDER BY updated_at DESC", (self.user['id'],))
        rows = cur.fetchall()
        conn.close()
        for r in self.tree.get_children():
            self.tree.delete(r)
        for row in rows:
            self.tree.insert("", "end", values=(row["id"], row["title"], row["username"], row["category"], row["tags"], row["updated_at"]))

    def on_select_credential(self, event):
        sel = self.tree.selection()
        if not sel: return
        item = self.tree.item(sel[0])['values']
        cid = item[0]
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT title,username,password_blob,notes,category,tags,created_at,updated_at,last_used FROM credentials WHERE id=? AND user_id=?", (cid, self.user['id']))
        row = cur.fetchone()
        conn.close()
        if row:
            title = row["title"]; username = row["username"]; blob = row["password_blob"]
            notes = row["notes"]; category = row["category"]; tags = row["tags"]
            created_at = row["created_at"]; updated_at = row["updated_at"]; last_used = row["last_used"]
            try:
                clear_text = decrypt_blob(self.fernet, blob)
            except Exception:
                clear_text = "[DECRYPTION FAILED]"
            text = f"Title: {title}\nUsername: {username}\nPassword: {'*'*8}\nCategory: {category}\nTags: {tags}\nCreated: {created_at}\nUpdated: {updated_at}\nLast Used: {last_used}\nNotes:\n{notes}"
            self.detail_text.delete("1.0", tk.END)
            self.detail_text.insert(tk.END, text)

    def open_add_window(self):
        if not self.user: return
        win = tk.Toplevel(self.root)
        win.title("Add Credential")
        entries = {}
        labels = ["Title","Username","Password","Category","Tags","Notes"]
        for i, lab in enumerate(labels):
            tk.Label(win, text=lab).grid(row=i, column=0, sticky='e')
            if lab == "Notes":
                e = tk.Text(win, width=40, height=6); e.grid(row=i, column=1, padx=6, pady=6)
            else:
                e = tk.Entry(win, width=40); e.grid(row=i, column=1, padx=6, pady=6)
            entries[lab.lower()] = e

        def gen_pw():
            pw = generate_password()
            entries['password'].delete(0, tk.END)
            entries['password'].insert(0, pw)

        tk.Button(win, text="Generate Password", command=gen_pw).grid(row=2, column=2, padx=6)
        tk.Button(win, text="Save", bg="#4CAF50", fg="white", command=lambda: self.add_credential(entries, win)).grid(row=len(labels), column=0, columnspan=2, pady=8)

    def add_credential(self, entries, win):
        title = entries['title'].get().strip()
        username = entries['username'].get().strip()
        password = entries['password'].get().strip()
        category = entries['category'].get().strip()
        tags = entries['tags'].get().strip()
        notes = entries['notes'].get("1.0", tk.END).strip() if isinstance(entries['notes'], tk.Text) else entries['notes'].get().strip()
        if not title or not password:
            messagebox.showerror("Error", "Title and password required")
            return
        blob = encrypt_blob(self.fernet, password)
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("INSERT INTO credentials (user_id,title,username,password_blob,notes,category,tags) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (self.user['id'], title, username, blob, notes, category, tags))
        conn.commit()
        conn.close()
        messagebox.showinfo("Saved", "Credential saved")
        win.destroy()
        self.load_credentials()

    def open_edit_window(self):
        sel = self.tree.selection()
        if not sel: return
        cid = self.tree.item(sel[0])['values'][0]
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT title,username,password_blob,notes,category,tags FROM credentials WHERE id=? AND user_id=?", (cid, self.user['id']))
        row = cur.fetchone()
        conn.close()
        if not row: return
        title = row["title"]; username = row["username"]; blob = row["password_blob"]
        notes = row["notes"]; category = row["category"]; tags = row["tags"]
        try:
            clear_pw = decrypt_blob(self.fernet, blob)
        except Exception:
            clear_pw = ""

        win = tk.Toplevel(self.root)
        win.title("Edit Credential")
        entries = {}
        labels = ["Title","Username","Password","Category","Tags","Notes"]
        values = [title, username, clear_pw, category, tags, notes]
        for i, lab in enumerate(labels):
            tk.Label(win, text=lab).grid(row=i, column=0, sticky='e')
            if lab == "Notes":
                e = tk.Text(win, width=40, height=6); e.grid(row=i, column=1, padx=6, pady=6)
                e.insert("1.0", values[i])
            else:
                e = tk.Entry(win, width=40); e.grid(row=i, column=1, padx=6, pady=6)
                e.insert(0, values[i])
            entries[lab.lower()] = e

        def save_edit():
            t = entries['title'].get().strip()
            u = entries['username'].get().strip()
            p = entries['password'].get().strip()
            cat = entries['category'].get().strip()
            tg = entries['tags'].get().strip()
            nt = entries['notes'].get("1.0", tk.END).strip() if isinstance(entries['notes'], tk.Text) else entries['notes'].get().strip()
            if not t or not p:
                messagebox.showerror("Error", "Title and password required")
                return
            blob2 = encrypt_blob(self.fernet, p)
            conn = get_connection()
            cur = conn.cursor()
            cur.execute("""UPDATE credentials SET title=?, username=?, password_blob=?, notes=?, category=?, tags=?, updated_at=CURRENT_TIMESTAMP
                           WHERE id=? AND user_id=?""", (t, u, blob2, nt, cat, tg, cid, self.user['id']))
            conn.commit()
            conn.close()
            messagebox.showinfo("Saved", "Credential updated")
            win.destroy()
            self.load_credentials()

        tk.Button(win, text="Save Changes", command=save_edit, bg="#58d68d", fg="white").grid(row=len(labels), column=0, columnspan=2, pady=8)

    def delete_selected(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showerror("Error", "Select a credential")
            return
        if not messagebox.askyesno("Confirm", "Delete selected credential?"):
            return
        cid = self.tree.item(sel[0])['values'][0]
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("DELETE FROM credentials WHERE id=? AND user_id=?", (cid, self.user['id']))
        conn.commit()
        conn.close()
        messagebox.showinfo("Deleted", "Credential deleted")
        self.load_credentials()

    # ---------------- Clipboard & Auto-clear ----------------
    def copy_password_to_clipboard(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showerror("Error", "Select a credential")
            return
        cid = self.tree.item(sel[0])['values'][0]
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT password_blob FROM credentials WHERE id=? AND user_id=?", (cid, self.user['id']))
        row = cur.fetchone()
        conn.close()
        if not row:
            messagebox.showerror("Error", "Not found")
            return
        blob = row["password_blob"]
        try:
            pw = decrypt_blob(self.fernet, blob)
        except Exception:
            messagebox.showerror("Error", "Decryption error")
            return
        pyperclip.copy(pw)
        messagebox.showinfo("Copied", f"Password copied to clipboard. It will clear in {AUTO_CLEAR_SECONDS} seconds.")
        threading.Thread(target=self._clear_clipboard_after, daemon=True).start()
        # update last_used
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("UPDATE credentials SET last_used=CURRENT_TIMESTAMP WHERE id=? AND user_id=?", (cid, self.user['id']))
        conn.commit()
        conn.close()

    def _clear_clipboard_after(self):
        time.sleep(AUTO_CLEAR_SECONDS)
        try:
            pyperclip.copy("")
        except Exception:
            pass

    # ---------------- Export / Import ----------------
    def export_encrypted(self):
        if not self.user:
            return
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON","*.json")])
        if not path:
            return
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT title,username,password_blob,notes,category,tags,created_at,updated_at FROM credentials WHERE user_id=?", (self.user['id'],))
        rows = cur.fetchall()
        conn.close()
        out = {
            "meta": {"exported_at": datetime.utcnow().isoformat(), "user": self.user['username']},
            "salt": base64.b64encode(self.salt).decode() if self.salt else None,
            "items": []
        }
        for r in rows:
            out["items"].append({
                "title": r["title"],
                "username": r["username"],
                "password_blob": base64.b64encode(r["password_blob"]).decode(),
                "notes": r["notes"],
                "category": r["category"],
                "tags": r["tags"],
                "created_at": r["created_at"],
                "updated_at": r["updated_at"]
            })
        with open(path, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2)
        messagebox.showinfo("Exported", f"Exported to {path}")

    def import_encrypted(self):
        if not self.user:
            return
        path = filedialog.askopenfilename(filetypes=[("JSON","*.json")])
        if not path:
            return
        if not messagebox.askyesno("Confirm", "Importing will add items to your vault. Continue?"):
            return
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        file_salt_b64 = data.get("salt")
        if file_salt_b64:
            file_salt = base64.b64decode(file_salt_b64)
            if self.salt and file_salt != self.salt:
                if not messagebox.askyesno("Salt mismatch", "Export uses a different salt. Import may fail to decrypt. Continue?"):
                    return
        imported = 0
        conn = get_connection()
        cur = conn.cursor()
        for it in data.get("items", []):
            blob = base64.b64decode(it["password_blob"])
            cur.execute("INSERT INTO credentials (user_id,title,username,password_blob,notes,category,tags) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (self.user['id'], it.get("title"), it.get("username"), blob, it.get("notes"), it.get("category"), it.get("tags")))
            imported += 1
        conn.commit()
        conn.close()
        messagebox.showinfo("Imported", f"Imported {imported} items.")
        self.load_credentials()

    # ---------------- Audit / Reports ----------------
    def show_audit(self):
        if not self.user:
            return
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT id,title,password_blob,updated_at,last_used FROM credentials WHERE user_id=?", (self.user['id'],))
        rows = cur.fetchall()
        conn.close()
        weak = []
        old = []
        now = datetime.utcnow()
        for r in rows:
            cid = r["id"]; title = r["title"]; blob = r["password_blob"]
            try:
                pwd = decrypt_blob(self.fernet, blob)
            except Exception:
                continue
            score = password_strength(pwd)
            if score <= 2:
                weak.append((title, score))
            updated_at = r["updated_at"]
            if updated_at:
                try:
                    # updated_at can be string; try parse
                    if isinstance(updated_at, str):
                        updated_dt = datetime.fromisoformat(updated_at)
                    else:
                        updated_dt = updated_at
                    age_days = (now - updated_dt).days
                    if age_days > 365:
                        old.append((title, age_days))
                except Exception:
                    pass
        out = "Password Audit Report\n\n"
        out += f"Weak passwords ({len(weak)}):\n"
        for t,s in weak[:50]:
            out += f" - {t} (score {s}/6)\n"
        out += f"\nOld passwords (>1 year) ({len(old)}):\n"
        for t,d in old[:50]:
            out += f" - {t} (last update {d} days)\n"
        messagebox.showinfo("Audit", out)

    # ---------------- Inactivity / Lock ----------------
    def check_inactivity(self):
        if not self._running:
            return
        now = datetime.now()
        if self.user and (now - self.last_activity) > self.auto_lock_after:
            self.lock_app()
        self.root.after(1000, self.check_inactivity)

    def lock_app(self):
        self.fernet = None
        self.user = None
        self.salt = None
        self.notebook.select(0)
        self.notebook.tab(1, state='disabled')
        messagebox.showinfo("Locked", "App locked due to inactivity. Please login again.")

    def mark_activity(self, event=None):
        self.last_activity = datetime.now()

    # ---------------- Clean shutdown ----------------
    def shutdown(self):
        self._running = False
        self.root.destroy()

# ----------------------------- Run -----------------------------
def main():
    root = tk.Tk()
    app = PasswordManagerApp(root)
    for seq in ("<Key>", "<Button>", "<Motion>"):
        root.bind_all(seq, lambda e: app.mark_activity())
    root.protocol("WM_DELETE_WINDOW", app.shutdown)
    root.mainloop()

if __name__ == "__main__":
    main()

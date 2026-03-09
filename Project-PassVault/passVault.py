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
import socket
import pymongo
from pymongo import MongoClient
from bson.objectid import ObjectId
from dotenv import load_dotenv
from datetime import datetime, timedelta
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, Label

# Crypto libs
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet, InvalidToken
import bcrypt
import pyperclip
import string

# ----------------------------- CONFIG -----------------------------
load_dotenv()
MONGO_URI = "mongodb+srv://manankamboj66_db_user:HeZJf1a7BKEQq3IF@globaldb.jmzxyvp.mongodb.net/?appName=GlobalDB"
DB_NAME = "passVault"

AUTO_CLEAR_SECONDS = 15          # clipboard clear seconds
AUTO_LOCK_MINUTES = 5           # lock app after inactivity
PBKDF2_ITERATIONS = 200_000     # key derivation iterations
SALT_BYTES = 16                 # salt bytes to store per user

# ----------------------------- HYBRID DB MANAGER -----------------------------
def is_online():
    """Check if internet connection is available."""
    try:
        # Use a short timeout to check connectivity to a reliable host
        socket.setdefaulttimeout(2)
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect(("8.8.8.8", 53))
        return True
    except (socket.timeout, socket.error):
        return False

class HybridDatabase:
    def __init__(self):
        self.local_db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vault.db")
        self.mongo_uri = MONGO_URI
        self.db_name = DB_NAME
        self.online = False
        self.mongo_client = None
        self.mongo_db = None
        self.init_local_db()
        self.check_connection()

    def init_local_db(self):
        conn = sqlite3.connect(self.local_db_path)
        cursor = conn.cursor()
        # Users table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                _id TEXT PRIMARY KEY,
                username TEXT UNIQUE,
                password_hash BLOB,
                salt BLOB,
                created_at TEXT
            )
        """)
        # Credentials table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS credentials (
                _id TEXT PRIMARY KEY,
                user_id TEXT,
                title TEXT,
                username TEXT,
                password_blob BLOB,
                notes TEXT,
                category TEXT,
                tags TEXT,
                created_at TEXT,
                updated_at TEXT,
                last_used TEXT,
                sync_status TEXT DEFAULT 'synced'
            )
        """)
        conn.commit()
        conn.close()

    def check_connection(self):
        self.online = is_online()
        if self.online:
            try:
                if self.mongo_client is None:
                    if "cluster0.mongodb.net" not in self.mongo_uri:
                        self.mongo_client = MongoClient(self.mongo_uri, serverSelectionTimeoutMS=2000)
                        self.mongo_db = self.mongo_client[self.db_name]
                        # Verify connection
                        self.mongo_client.server_info()
                        # Create indexes
                        self.mongo_db.users.create_index("username", unique=True)
                        self.mongo_db.credentials.create_index([("user_id", pymongo.ASCENDING), ("title", pymongo.ASCENDING)])
                        self.mongo_db.credentials.create_index([("user_id", pymongo.ASCENDING), ("category", pymongo.ASCENDING)])
                        self.mongo_db.credentials.create_index([("user_id", pymongo.ASCENDING), ("updated_at", pymongo.DESCENDING)])
                    else:
                        self.online = False # Still placeholder
                else:
                    self.mongo_client.server_info()
            except Exception:
                self.online = False
        return self.online

    def get_collection(self, name):
        return HybridCollection(self, name)

    @property
    def users(self):
        return self.get_collection("users")

    @property
    def credentials(self):
        return self.get_collection("credentials")

class HybridCollection:
    def __init__(self, db_manager, name):
        self.db_manager = db_manager
        self.name = name

    def insert_one(self, doc):
        # Ensure _id exists
        if "_id" not in doc:
            doc["_id"] = ObjectId()
        
        doc_copy = doc.copy()
        str_id = str(doc_copy["_id"])
        
        # Save locally first
        conn = sqlite3.connect(self.db_manager.local_db_path)
        cursor = conn.cursor()
        if self.name == "users":
            cursor.execute(
                "INSERT INTO users (_id, username, password_hash, salt, created_at) VALUES (?, ?, ?, ?, ?)",
                (str_id, doc.get("username"), doc.get("password_hash"), doc.get("salt"), doc.get("created_at").isoformat() if isinstance(doc.get("created_at"), datetime) else str(doc.get("created_at")))
            )
        else: # credentials
            cursor.execute(
                """INSERT INTO credentials (_id, user_id, title, username, password_blob, notes, category, tags, created_at, updated_at, last_used, sync_status)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (str_id, doc.get("user_id"), doc.get("title"), doc.get("username"), doc.get("password_blob"), 
                 doc.get("notes"), doc.get("category"), doc.get("tags"), 
                 doc.get("created_at").isoformat() if isinstance(doc.get("created_at"), datetime) else str(doc.get("created_at")),
                 doc.get("updated_at").isoformat() if isinstance(doc.get("updated_at"), datetime) else str(doc.get("updated_at")),
                 doc.get("last_used").isoformat() if isinstance(doc.get("last_used"), datetime) else str(doc.get("last_used")),
                 'pending_save' if not self.db_manager.online else 'synced')
            )
        conn.commit()
        conn.close()

        # Try online if connected
        if self.db_manager.online and self.db_manager.mongo_db is not None:
            try:
                self.db_manager.mongo_db[self.name].insert_one(doc)
            except pymongo.errors.DuplicateKeyError:
                # Re-raise for UI handling
                raise
            except Exception as e:
                print(f"Failed to insert online: {e}")

    def find_one(self, query):
        # Strategy: check online first if available, otherwise fallback to local
        result = None
        if self.db_manager.online and self.db_manager.mongo_db is not None:
            try:
                result = self.db_manager.mongo_db[self.name].find_one(query)
                if result:
                    # Cache locally
                    self._cache_locally(result)
                    return result
            except Exception:
                pass
        
        # Fallback to local
        conn = sqlite3.connect(self.db_manager.local_db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        if self.name == "users":
            if "username" in query:
                cursor.execute("SELECT * FROM users WHERE username = ?", (query["username"],))
            elif "_id" in query:
                cursor.execute("SELECT * FROM users WHERE _id = ?", (str(query["_id"]),))
        else: # credentials
            if "_id" in query:
                cursor.execute("SELECT * FROM credentials WHERE _id = ?", (str(query["_id"]),))
            elif "user_id" in query and len(query) == 1:
                cursor.execute("SELECT * FROM credentials WHERE user_id = ?", (query["user_id"],))
        
        row = cursor.fetchone()
        conn.close()
        
        if row:
            res = dict(row)
            res["_id"] = ObjectId(res["_id"]) if ObjectId.is_valid(res["_id"]) else res["_id"]
            if "created_at" in res and res["created_at"]: res["created_at"] = self._parse_dt(res["created_at"])
            if "updated_at" in res and res["updated_at"]: res["updated_at"] = self._parse_dt(res["updated_at"])
            if "last_used" in res and res["last_used"]: res["last_used"] = self._parse_dt(res["last_used"])
            return res
        return None

    def find(self, query):
        # We need a cursor-like object. For simplicity, we'll return a HybridCursor
        return HybridCursor(self.db_manager, self.name, query)

    def update_one(self, filter_query, update_data):
        # Update local first
        conn = sqlite3.connect(self.db_manager.local_db_path)
        cursor = conn.cursor()
        
        set_clause = update_data.get("$set", {})
        if self.name == "credentials":
            str_id = str(filter_query.get("_id"))
            
            # Construct dynamic UPDATE query
            fields = []
            values = []
            for k, v in set_clause.items():
                if k == "updated_at" or k == "last_used":
                    v = v.isoformat() if isinstance(v, datetime) else str(v)
                fields.append(f"{k} = ?")
                values.append(v)
            
            if not self.db_manager.online:
                fields.append("sync_status = ?")
                values.append('pending_save')
            
            query = f"UPDATE credentials SET {', '.join(fields)} WHERE _id = ?"
            values.append(str_id)
            cursor.execute(query, tuple(values))
        
        conn.commit()
        conn.close()

        # Update online
        if self.db_manager.online and self.db_manager.mongo_db is not None:
            try:
                self.db_manager.mongo_db[self.name].update_one(filter_query, update_data)
            except Exception as e:
                print(f"Failed to update online: {e}")

    def delete_one(self, filter_query):
        str_id = str(filter_query.get("_id"))
        
        # Local handling
        conn = sqlite3.connect(self.db_manager.local_db_path)
        cursor = conn.cursor()
        if self.db_manager.online:
            cursor.execute(f"DELETE FROM {self.name} WHERE _id = ?", (str_id,))
        else:
            if self.name == "credentials":
                # Mark for deletion when back online
                cursor.execute("UPDATE credentials SET sync_status = 'pending_delete' WHERE _id = ?", (str_id,))
            else:
                cursor.execute(f"DELETE FROM {self.name} WHERE _id = ?", (str_id,))
        conn.commit()
        conn.close()

        # Online handling
        if self.db_manager.online and self.db_manager.mongo_db is not None:
            try:
                self.db_manager.mongo_db[self.name].delete_one(filter_query)
            except Exception as e:
                print(f"Failed to delete online: {e}")

    def _cache_locally(self, doc):
        conn = sqlite3.connect(self.db_manager.local_db_path)
        cursor = conn.cursor()
        str_id = str(doc["_id"])
        if self.name == "users":
            cursor.execute("INSERT OR REPLACE INTO users (_id, username, password_hash, salt, created_at) VALUES (?, ?, ?, ?, ?)",
                (str_id, doc.get("username"), doc.get("password_hash"), doc.get("salt"), doc.get("created_at").isoformat() if isinstance(doc.get("created_at"), datetime) else str(doc.get("created_at"))))
        else: # credentials
            cursor.execute("""
                INSERT OR REPLACE INTO credentials (_id, user_id, title, username, password_blob, notes, category, tags, created_at, updated_at, last_used, sync_status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'synced')
            """, (str_id, doc.get("user_id"), doc.get("title"), doc.get("username"), doc.get("password_blob"), 
                  doc.get("notes"), doc.get("category"), doc.get("tags"),
                  doc.get("created_at").isoformat() if isinstance(doc.get("created_at"), datetime) else str(doc.get("created_at")),
                  doc.get("updated_at").isoformat() if isinstance(doc.get("updated_at"), datetime) else str(doc.get("updated_at")),
                  doc.get("last_used").isoformat() if isinstance(doc.get("last_used"), datetime) else str(doc.get("last_used")) if doc.get("last_used") else None))
        conn.commit()
        conn.close()

    def _parse_dt(self, val):
        if val is None: return None
        if isinstance(val, datetime): return val
        try:
            return datetime.fromisoformat(val)
        except:
            return val

class HybridCursor:
    def __init__(self, db_manager, collection_name, query):
        self.db_manager = db_manager
        self.collection_name = collection_name
        self.query = query
        self.sort_params = None
        self._data = None

    def sort(self, field, direction=1):
        self.sort_params = (field, direction)
        return self

    def _fetch(self):
        if self._data is not None: return
        
        # Priority: Online
        if self.db_manager.online and self.db_manager.mongo_db is not None:
            try:
                cursor = self.db_manager.mongo_db[self.collection_name].find(self.query)
                if self.sort_params:
                    cursor = cursor.sort(self.sort_params[0], self.sort_params[1])
                self._data = list(cursor)
                return
            except Exception:
                pass
        
        # Fallback: Local
        conn = sqlite3.connect(self.db_manager.local_db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        where_clauses = ["sync_status != 'pending_delete'"]
        params = []
        if "user_id" in self.query:
            where_clauses.append("user_id = ?")
            params.append(self.query["user_id"])
        
        q_str = f"SELECT * FROM {self.collection_name}"
        if where_clauses:
            q_str += " WHERE " + " AND ".join(where_clauses)
            
        if self.sort_params:
            direction = "ASC" if self.sort_params[1] == 1 else "DESC"
            q_str += f" ORDER BY {self.sort_params[0]} {direction}"
            
        cursor.execute(q_str, tuple(params))
        rows = cursor.fetchall()
        conn.close()
        
        self._data = []
        for row in rows:
            res = dict(row)
            res["_id"] = ObjectId(res["_id"]) if ObjectId.is_valid(res["_id"]) else res["_id"]
            self._data.append(res)

    def __iter__(self):
        self._fetch()
        return iter(self._data)

    def __len__(self):
        self._fetch()
        return len(self._data)

# Global Instance
db_instance = HybridDatabase()

def get_db():
    return db_instance

def initialize_database():
    # Already handled by HybridDatabase class
    pass

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
        self.root.after(2000, self.background_sync_loop)

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
        
        # Status Bar
        self.status_bar = tk.Frame(self.root, bd=1, relief='sunken', height=25)
        self.status_bar.pack(side='bottom', fill='x')
        self.status_label = tk.Label(self.status_bar, text="Checking connection...")
        self.status_label.pack(side='left', padx=10)
        self.sync_label = tk.Label(self.status_bar, text="")
        self.sync_label.pack(side='right', padx=10)

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
                db = get_db()
                
                user_doc = {
                    "username": username,
                    "password_hash": pw_hash,
                    "salt": salt,
                    "created_at": datetime.utcnow()
                }
                db.users.insert_one(user_doc)
                messagebox.showinfo("Success", "Account created. Please login.")
                win.destroy()
            except pymongo.errors.DuplicateKeyError:
                messagebox.showerror("Error", "Username already exists.")

        tk.Button(win, text="Create", command=create).grid(row=3, column=0, columnspan=2, pady=8)

    def login(self):
        username = self.login_username.get().strip()
        pw = self.login_password.get().strip()
        if not username or not pw:
            messagebox.showerror("Error", "Enter username and password")
            return
        db = get_db()
        
        row = db.users.find_one({"username": username})
        if not row:
            messagebox.showerror("Error", "User not found")
            return
        user_id = str(row["_id"])
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
        db = get_db()
        if db is None: return
        
        filter_query = {"user_id": self.user['id']}
        if q:
            filter_query["$or"] = [
                {"title": {"$regex": q, "$options": "i"}},
                {"username": {"$regex": q, "$options": "i"}},
                {"category": {"$regex": q, "$options": "i"}},
                {"tags": {"$regex": q, "$options": "i"}}
            ]
        
        rows = list(db.credentials.find(filter_query).sort("updated_at", pymongo.DESCENDING))
        
        for r in self.tree.get_children():
            self.tree.delete(r)
        for row in rows:
            self.tree.insert("", "end", values=(str(row["_id"]), row.get("title"), row.get("username"), row.get("category"), row.get("tags"), row.get("updated_at")))

    def on_select_credential(self, event):
        sel = self.tree.selection()
        if not sel: return
        item = self.tree.item(sel[0])['values']
        cid = item[0]
        db = get_db()
        if db is None: return
        row = db.credentials.find_one({"_id": ObjectId(cid), "user_id": self.user['id']})
        if row:
            title = row.get("title"); username = row.get("username"); blob = row.get("password_blob")
            notes = row.get("notes"); category = row.get("category"); tags = row.get("tags")
            created_at = row.get("created_at"); updated_at = row.get("updated_at"); last_used = row.get("last_used")
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
        db = get_db()
        if db is None: return
        doc = {
            "user_id": self.user['id'],
            "title": title,
            "username": username,
            "password_blob": blob,
            "notes": notes,
            "category": category,
            "tags": tags,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow()
        }
        db.credentials.insert_one(doc)
        messagebox.showinfo("Saved", "Credential saved")
        win.destroy()
        self.load_credentials()

    def open_edit_window(self):
        sel = self.tree.selection()
        if not sel: return
        cid = self.tree.item(sel[0])['values'][0]
        db = get_db()
        if db is None: return
        row = db.credentials.find_one({"_id": ObjectId(cid), "user_id": self.user['id']})
        if not row: return
        title = row.get("title"); username = row.get("username"); blob = row.get("password_blob")
        notes = row.get("notes"); category = row.get("category"); tags = row.get("tags")
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
            db = get_db()
            if db is None: return
            db.credentials.update_one(
                {"_id": ObjectId(cid), "user_id": self.user['id']},
                {"$set": {
                    "title": t,
                    "username": u,
                    "password_blob": blob2,
                    "notes": nt,
                    "category": cat,
                    "tags": tg,
                    "updated_at": datetime.utcnow()
                }}
            )
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
        db = get_db()
        if db is None: return
        db.credentials.delete_one({"_id": ObjectId(cid), "user_id": self.user['id']})
        messagebox.showinfo("Deleted", "Credential deleted")
        self.load_credentials()

    # ---------------- Clipboard & Auto-clear ----------------
    def copy_password_to_clipboard(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showerror("Error", "Select a credential")
            return
        cid = self.tree.item(sel[0])['values'][0]
        db = get_db()
        if db is None: return
        row = db.credentials.find_one({"_id": ObjectId(cid), "user_id": self.user['id']})
        if not row:
            messagebox.showerror("Error", "Not found")
            return
        blob = row.get("password_blob")
        try:
            pw = decrypt_blob(self.fernet, blob)
        except Exception:
            messagebox.showerror("Error", "Decryption error")
            return
        pyperclip.copy(pw)
        messagebox.showinfo("Copied", f"Password copied to clipboard. It will clear in {AUTO_CLEAR_SECONDS} seconds.")
        threading.Thread(target=self._clear_clipboard_after, daemon=True).start()
        # update last_used
        db.credentials.update_one(
            {"_id": ObjectId(cid), "user_id": self.user['id']},
            {"$set": {"last_used": datetime.utcnow()}}
        )

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
        db = get_db()
        if db is None: return
        rows = list(db.credentials.find({"user_id": self.user['id']}))
        out = {
            "meta": {"exported_at": datetime.utcnow().isoformat(), "user": self.user['username']},
            "salt": base64.b64encode(self.salt).decode() if self.salt else None,
            "items": []
        }
        for r in rows:
            out["items"].append({
                "title": r.get("title"),
                "username": r.get("username"),
                "password_blob": base64.b64encode(r.get("password_blob")).decode(),
                "notes": r.get("notes"),
                "category": r.get("category"),
                "tags": r.get("tags"),
                "created_at": r.get("created_at").isoformat() if r.get("created_at") else None,
                "updated_at": r.get("updated_at").isoformat() if r.get("updated_at") else None
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
        db = get_db()
        if db is None: return
        for it in data.get("items", []):
            blob = base64.b64decode(it["password_blob"])
            doc = {
                "user_id": self.user['id'],
                "title": it.get("title"),
                "username": it.get("username"),
                "password_blob": blob,
                "notes": it.get("notes"),
                "category": it.get("category"),
                "tags": it.get("tags"),
                "created_at": datetime.fromisoformat(it["created_at"]) if it.get("created_at") else datetime.utcnow(),
                "updated_at": datetime.fromisoformat(it["updated_at"]) if it.get("updated_at") else datetime.utcnow()
            }
            db.credentials.insert_one(doc)
            imported += 1
        messagebox.showinfo("Imported", f"Imported {imported} items.")
        self.load_credentials()

    # ---------------- Audit / Reports ----------------
    def show_audit(self):
        if not self.user:
            return
        db = get_db()
        if db is None: return
        rows = list(db.credentials.find({"user_id": self.user['id']}))
        weak = []
        old = []
        now = datetime.utcnow()
        for r in rows:
            cid = str(r["_id"]); title = r.get("title"); blob = r.get("password_blob")
            try:
                pwd = decrypt_blob(self.fernet, blob)
            except Exception:
                continue
            score = password_strength(pwd)
            if score <= 2:
                weak.append((title, score))
            updated_at = r.get("updated_at")
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

    # ---------------- Sync Logic ----------------
    def background_sync_loop(self):
        if not self._running:
            return
        
        was_online = db_instance.online
        is_now_online = db_instance.check_connection()
        
        status_text = "🟢 Online (MongoDB Atlas)" if is_now_online else "🔴 Offline (Local SQLite)"
        self.status_label.config(text=status_text, fg="green" if is_now_online else "red")
        
        if is_now_online:
            threading.Thread(target=self.perform_sync, daemon=True).start()
            
        self.root.after(10000, self.background_sync_loop)

    def perform_sync(self):
        if not db_instance.online or db_instance.mongo_db is None:
            return
            
        try:
            conn = sqlite3.connect(db_instance.local_db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # 1. Handle pending saves/updates
            cursor.execute("SELECT * FROM credentials WHERE sync_status = 'pending_save'")
            pending = cursor.fetchall()
            for p in pending:
                doc = dict(p)
                doc["_id"] = ObjectId(doc["_id"])
                sync_id = doc.pop("_id")
                doc.pop("sync_status")
                # Upsert into Mongo
                db_instance.mongo_db.credentials.replace_one({"_id": sync_id}, doc, upsert=True)
                # Mark as synced locally
                cursor.execute("UPDATE credentials SET sync_status = 'synced' WHERE _id = ?", (str(sync_id),))
            
            # 2. Handle pending deletes
            cursor.execute("SELECT * FROM credentials WHERE sync_status = 'pending_delete'")
            to_delete = cursor.fetchall()
            for d in to_delete:
                db_instance.mongo_db.credentials.delete_one({"_id": ObjectId(d["_id"])})
                cursor.execute("DELETE FROM credentials WHERE _id = ?", (d["_id"],))
            
            conn.commit()
            conn.close()
            
            if len(pending) > 0 or len(to_delete) > 0:
                self.sync_label.config(text=f"Last Sync: {datetime.now().strftime('%H:%M:%S')} (Updated {len(pending)+len(to_delete)} items)")
        except Exception as e:
            print(f"Sync error: {e}")

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

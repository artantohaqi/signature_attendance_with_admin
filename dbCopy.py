import sqlite3, os
from flask import g
from werkzeug.security import generate_password_hash

BASE_DIR = os.path.dirname(__file__)
DB_PATH = os.path.join(BASE_DIR, "data.db")

def get_db():
    if "_database" not in g:
        g._database = sqlite3.connect(
            DB_PATH,
            timeout=10,              # tunggu 10 detik kalau database sedang lock
            check_same_thread=False  # izinkan multi-thread akses (dibutuhkan Flask)
        )
        g._database.row_factory = sqlite3.Row
    return g._database

def init_db(db):
    cur = db.cursor()

    # Aktifkan WAL mode supaya read/write bisa paralel
    cur.execute("PRAGMA journal_mode=WAL;")

    # Table departements
    cur.execute('''
        CREATE TABLE IF NOT EXISTS departements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            departement TEXT UNIQUE NOT NULL
        )
    ''')
    cur.execute("SELECT COUNT(*) FROM departements")
    if cur.fetchone()[0] == 0:
        cur.execute("INSERT INTO departements (id, departement) VALUES (?, ?)", (1, 'IT'))

    # Table users
    cur.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nama_lengkap TEXT,
            email TEXT UNIQUE,
            departement_id INTEGER,
            created_at TEXT,
            FOREIGN KEY(departement_id) REFERENCES departements(id)
        )
    ''')

    # Table uploads
    cur.execute('''
        CREATE TABLE IF NOT EXISTS uploads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            departement_id INTEGER,
            email TEXT,
            files TEXT,
            status TEXT,
            note TEXT,
            distance REAL,
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(departement_id) REFERENCES departements(id)
        )
    ''')

    # Table signatures
    cur.execute('''
        CREATE TABLE IF NOT EXISTS signatures (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            sig_json TEXT,
            created_at TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')

    # Table attendance
    cur.execute('''
        CREATE TABLE IF NOT EXISTS attendance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            email TEXT,
            timestamp TEXT,
            status TEXT,
            note TEXT,
            distance REAL,
            reason TEXT,
            departement_id INTEGER,
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(departement_id) REFERENCES departements(id)
        )
    ''')

    # Table admins
    cur.execute('''
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    ''')
    cur.execute("SELECT COUNT(*) FROM admins")
    if cur.fetchone()[0] == 0:
        cur.execute("INSERT INTO admins (username,password_hash) VALUES (?,?)",
                    ("admin", generate_password_hash("admin123")))

    db.commit()

def close_db(e=None):
    db = g.pop("_database", None)
    if db is not None:
        db.close()

def init_app(app):
    app.teardown_appcontext(close_db)

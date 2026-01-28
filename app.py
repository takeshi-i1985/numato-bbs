import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "bbs_secret_key_change_me"

# Renderでも安全な保存先
DB_NAME = "/tmp/bbs.db"
print("DB FILE PATH:", os.path.abspath(DB_NAME))

# ================= DB接続 =================
def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

# ================= DB初期化 =================
def init_db():
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()

    # ユーザー
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        is_admin INTEGER DEFAULT 0,
        created TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # 投稿
    cur.execute("""
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        body TEXT,
        posted TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        ip TEXT,
        club TEXT
    )
    """)

    # 管理者アカウント自動作成
    cur.execute("SELECT * FROM users WHERE username = 'teacher'")
    if not cur.fetchone():
        cur.execute(
            "INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 1)",
            ("teacher", generate_password_hash("9999"))
        )
        print("Admin created: teacher / 9999")

    conn.commit()
    conn.close()

# 起動時必ず実行（Render対応）
init_db()

# ================= ログイン判定 =================
def logged_in():
    return "user_id" in session

def is_admin():
    return session.get("is_admin") == 1

# ================= サイト全体ログイン必須 =================
@app.before_request
def require_login():
    allowed_endpoints = {"login", "static"}  # registerも封鎖

    if request.endpoint is None:
        return

    if request.endpoint not in allowed_endpoints and "user_id" not in session:
        return redirect(url_for("login"))

# ================= トップ（掲示板） =================
@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        body = request.form.get("body", "").strip()
        club = request.form.get("club")
        ip = request.remote_addr

        if body and club:
            conn = get_db()
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO messages (name, body, ip, club) VALUES (?, ?, ?, ?)",
                (session["username"], body, ip, club)
            )
            conn.commit()
            conn.close()
        return redirect(url_for("index"))

    mode = request.args.get("mode")
    club_filter = request.args.get("club")

    conn = get_db()
    cur = conn.cursor()

    if mode == "list":
        if club_filter:
            cur.execute("""
                SELECT *, datetime(posted, '+9 hours') AS posted_jst
                FROM messages WHERE club = ? ORDER BY id DESC
            """, (club_filter,))
        else:
            cur.execute("""
                SELECT *, datetime(posted, '+9 hours') AS posted_jst
                FROM messages ORDER BY id DESC
            """)
    else:
        if club_filter:
            cur.execute("""
                SELECT *, datetime(posted, '+9 hours') AS posted_jst
                FROM messages WHERE club = ? ORDER BY id DESC
            """, (club_filter,))
        else:
            cur.execute("""
                SELECT *, datetime(posted, '+9 hours') AS posted_jst
                FROM messages ORDER BY club, id DESC
            """)

    messages = cur.fetchall()
    conn.close()

    return render_template("index.html", messages=messages, mode=mode)

# ================= ログイン =================
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cur.fetchone()
        conn.close()

        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["is_admin"] = user["is_admin"]
            return redirect(url_for("index"))
        else:
            flash("ユーザー名またはパスワードが違います")

    return render_template("login.html")

# ================= ログアウト =================
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ================= 管理画面 =================
@app.route("/admin")
def admin():
    if not is_admin():
        return "管理者のみ", 403

    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT id, username, is_admin, created FROM users ORDER BY id DESC")
    users = cur.fetchall()

    cur.execute("""
        SELECT id, name, body,
               datetime(posted, '+9 hours') AS posted_jst,
               ip, club
        FROM messages ORDER BY id DESC
    """)
    messages = cur.fetchall()

    conn.close()
    return render_template("admin.html", users=users, messages=messages)

# ================= ローカル起動用 =================
if __name__ == "__main__":
    app.run()

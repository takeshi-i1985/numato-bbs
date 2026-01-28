import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "bbs_secret_key_change_me"

# Renderでも書き込み可能な場所
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

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        is_admin INTEGER DEFAULT 0,
        created TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

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


init_db()


# ================= ログイン判定 =================
def logged_in():
    return "user_id" in session

def is_admin():
    return session.get("is_admin") == 1


# ================= 全ページログイン制御 =================
@app.before_request
def require_login():
    if request.endpoint is None:
        return

    # 常に許可
    if request.endpoint in {"login", "static"}:
        return

    # registerは管理者のみ
    if request.endpoint == "register":
        if logged_in() and is_admin():
            return
        return redirect(url_for("login"))

    # それ以外はログイン必須
    if not logged_in():
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


# ================= 管理者専用：新規登録 =================
@app.route("/register", methods=["GET", "POST"])
def register():
    if not is_admin():
        return redirect(url_for("login"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        pw = request.form.get("password", "").strip()

        if not username:
            flash("ユーザー名を入力してください")
            return render_template("register.html")

        if not (pw.isdigit() and len(pw) == 4):
            flash("パスワードは4桁の数字で入力してください")
            return render_template("register.html")

        try:
            conn = get_db()
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, generate_password_hash(pw))
            )
            conn.commit()
            conn.close()
        except sqlite3.IntegrityError:
            flash("そのユーザー名はすでに登録されています")
            return render_template("register.html")

        flash("登録しました")
        return redirect(url_for("admin"))

    return render_template("register.html")


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

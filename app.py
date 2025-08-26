import os, csv, time, threading, sqlite3, json, re, requests, datetime
from flask import Flask, render_template, request, redirect, url_for, send_file, jsonify, flash
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from twilio.rest import Client
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt

load_dotenv()

DB_PATH = os.path.join("data", "app.db")
os.makedirs("data", exist_ok=True)
os.makedirs("uploads", exist_ok=True)

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY", "change_me")
bcrypt = Bcrypt(app)

# Auth setup
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

# Twilio
ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID", "")
AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN", "")
MSG_SERVICE_SID = os.getenv("TWILIO_MESSAGING_SERVICE_SID", "").strip()
FROM_NUMBER = os.getenv("TWILIO_FROM_NUMBER", "").strip()
PUBLIC_WEBHOOK_URL = os.getenv("PUBLIC_WEBHOOK_URL", "").strip()

client = Client(ACCOUNT_SID, AUTH_TOKEN)

def db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = db(); c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE, password TEXT, role TEXT, created_at TEXT
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS jobs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT, template TEXT,
        col_phone TEXT, col_name TEXT, col_company TEXT,
        csv_path TEXT, rate INTEGER,
        status TEXT, created_at TEXT,
        total INTEGER DEFAULT 0, sent INTEGER DEFAULT 0, skipped INTEGER DEFAULT 0, failed INTEGER DEFAULT 0,
        owner_id INTEGER
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS messages(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        job_id INTEGER, recipient_to TEXT, assigned_user_id INTEGER,
        direction TEXT, status TEXT, sid TEXT, error TEXT, body TEXT, ts REAL
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS suppressions(phone TEXT PRIMARY KEY)""")
    c.execute("""CREATE TABLE IF NOT EXISTS kv(key TEXT PRIMARY KEY, value TEXT)""")
    conn.commit(); conn.close()

    # bootstrap admin
    admin_email = os.getenv("ADMIN_EMAIL")
    admin_pw = os.getenv("ADMIN_PASSWORD")
    if admin_email and admin_pw:
        conn = db(); c = conn.cursor()
        c.execute("SELECT id FROM users WHERE email=?", (admin_email,))
        if not c.fetchone():
            hashed = bcrypt.generate_password_hash(admin_pw).decode("utf-8")
            c.execute("INSERT INTO users(email,password,role,created_at) VALUES(?,?,?,datetime('now'))",
                      (admin_email, hashed, "admin"))
            conn.commit()
        conn.close()

init_db()

class User(UserMixin):
    def __init__(self, row):
        self.id = row["id"]
        self.email = row["email"]
        self.role = row["role"]

@login_manager.user_loader
def load_user(user_id):
    conn = db(); c = conn.cursor()
    c.execute("SELECT * FROM users WHERE id=?", (user_id,))
    row = c.fetchone(); conn.close()
    if row: return User(row)
    return None

def is_opted_out(number: str) -> bool:
    conn = db(); c = conn.cursor()
    c.execute("SELECT phone FROM suppressions WHERE phone=?", (number,))
    row = c.fetchone(); conn.close()
    return row is not None

def add_suppression(number: str):
    conn = db(); c = conn.cursor()
    try:
        c.execute("INSERT OR IGNORE INTO suppressions(phone) VALUES(?)", (number,))
        conn.commit()
    finally:
        conn.close()

def remove_suppression(number: str):
    conn = db(); c = conn.cursor()
    try:
        c.execute("DELETE FROM suppressions WHERE phone=?", (number,))
        conn.commit()
    finally:
        conn.close()

def render_template_text(template_text: str, context: dict) -> str:
    def repl(m): return str(context.get(m.group(1).strip(), ""))
    return re.sub(r"\{\{\s*(.*?)\s*\}\}", repl, template_text)

def push_to_ghl(payload: dict):
    conn = db(); c = conn.cursor()
    c.execute("SELECT value FROM kv WHERE key='ghl_url'")
    row = c.fetchone(); ghl_url = row["value"] if row else ""
    c.execute("SELECT value FROM kv WHERE key='ghl_headers'")
    row = c.fetchone(); ghl_headers = row["value"] if row else ""
    conn.close()
    if not ghl_url: return False, "No GHL URL set"
    headers = {}
    if ghl_headers:
        try:
            headers = json.loads(ghl_headers)
        except Exception:
            pass
    try:
        r = requests.post(ghl_url, json=payload, headers=headers, timeout=10)
        return r.ok, f"{r.status_code}"
    except Exception as e:
        return False, str(e)

workers = {}

def assign_user(user_ids, strategy, idx, percents_map=None):
    if not user_ids: return None
    if strategy == "round_robin":
        return user_ids[idx % len(user_ids)]
    if strategy == "percent_split" and percents_map:
        # expand into a list by percent weights (sum=100)
        expanded = []
        for uid, pct in percents_map.items():
            expanded += [uid] * int(max(1, round(pct)))
        return expanded[idx % len(expanded)] if expanded else user_ids[idx % len(user_ids)]
    return None

def send_worker(job_id: int):
    conn = db(); c = conn.cursor()
    c.execute("SELECT * FROM jobs WHERE id=?", (job_id,))
    job = dict(c.fetchone())
    owner_id = job["owner_id"]
    conn.close()

    rate = max(1, int(job["rate"] or 30))
    delay = 60.0 / rate

    # load CSV
    rows = []
    with open(job["csv_path"], newline="") as f:
        reader = csv.DictReader(f)
        for r in reader: rows.append(r)

    # Load assignment data from job name meta (hack: store JSON after '::' if present)
    # Better would be a dedicated table; keeping minimal for clarity.
    strategy = "none"; selected_user_ids = []; percents_map = None
    if "::" in job["name"]:
        try:
            meta = json.loads(job["name"].split("::",1)[1])
            strategy = meta.get("strategy","none")
            selected_user_ids = meta.get("user_ids",[])
            percents_map = meta.get("percents")
        except Exception: pass

    total = len(rows)
    conn = db(); c = conn.cursor()
    c.execute("UPDATE jobs SET total=?, status='running' WHERE id=?", (total, job_id))
    conn.commit(); conn.close()

    sent = skipped = failed = 0
    for i, r in enumerate(rows):
        # pause?
        conn = db(); c = conn.cursor()
        c.execute("SELECT status FROM jobs WHERE id=?", (job_id,))
        status = c.fetchone()["status"]; conn.close()
        if status != "running": break

        to = (r.get(job["col_phone"] or "phone","") or "").strip()
        if not to:
            skipped += 1
            conn = db(); c = conn.cursor()
            c.execute("INSERT INTO messages(job_id, recipient_to, assigned_user_id, direction, status, sid, error, body, ts) VALUES(?,?,?,?,?,?,?,?,?)",
                      (job_id, "", None, "outbound", "skipped_no_number", "", "", "", time.time()))
            conn.commit(); conn.close()
            continue
        if is_opted_out(to):
            skipped += 1
            conn = db(); c = conn.cursor()
            c.execute("INSERT INTO messages(job_id, recipient_to, assigned_user_id, direction, status, sid, error, body, ts) VALUES(?,?,?,?,?,?,?,?,?)",
                      (job_id, to, None, "outbound", "skipped_opted_out", "", "", "", time.time()))
            conn.commit(); conn.close()
            continue

        ctx = {
            "name": r.get(job["col_name"] or "name",""),
            "company": r.get(job["col_company"] or "company","")
        }
        body = render_template_text(job["template"], ctx)

        # assign user id based on strategy
        assigned_uid = assign_user(selected_user_ids, strategy, i, percents_map)
        try:
            if MSG_SERVICE_SID:
                msg = client.messages.create(to=to, body=body, messaging_service_sid=MSG_SERVICE_SID)
            else:
                msg = client.messages.create(to=to, body=body, from_=FROM_NUMBER)
            sent += 1
            conn = db(); c = conn.cursor()
            c.execute("INSERT INTO messages(job_id, recipient_to, assigned_user_id, direction, status, sid, error, body, ts) VALUES(?,?,?,?,?,?,?,?,?)",
                      (job_id, to, assigned_uid, "outbound", "sent", msg.sid, "", body, time.time()))
            conn.commit(); conn.close()
        except Exception as e:
            failed += 1
            conn = db(); c = conn.cursor()
            c.execute("INSERT INTO messages(job_id, recipient_to, assigned_user_id, direction, status, sid, error, body, ts) VALUES(?,?,?,?,?,?,?,?,?)",
                      (job_id, to, assigned_uid, "outbound", "failed", "", str(e), body, time.time()))
            conn.commit(); conn.close()

        conn = db(); c = conn.cursor()
        c.execute("UPDATE jobs SET sent=?, skipped=?, failed=? WHERE id=?", (sent, skipped, failed, job_id))
        conn.commit(); conn.close()

        time.sleep(delay)

    conn = db(); c = conn.cursor()
    c.execute("SELECT status FROM jobs WHERE id=?", (job_id,))
    cur_status = c.fetchone()["status"]
    final_status = "complete" if cur_status == "running" else cur_status
    c.execute("UPDATE jobs SET status=? WHERE id=?", (final_status, job_id))
    conn.commit(); conn.close()

# Views
from functools import wraps
def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != "admin":
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return wrapper

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        pw = request.form["password"]
        conn = db(); c = conn.cursor()
        c.execute("SELECT * FROM users WHERE email=?", (email,))
        row = c.fetchone(); conn.close()
        if row and bcrypt.check_password_hash(row["password"], pw):
            login_user(User(row))
            return redirect(url_for("index"))
        flash("Invalid credentials")
    return render_template("login.html", webhook_url=PUBLIC_WEBHOOK_URL)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.route("/")
@login_required
def index():
    conn = db(); c = conn.cursor()
    if current_user.role == "admin":
        c.execute("SELECT j.*, u.email as owner_email FROM jobs j LEFT JOIN users u ON j.owner_id=u.id ORDER BY id DESC LIMIT 10")
    else:
        c.execute("SELECT j.*, u.email as owner_email FROM jobs j LEFT JOIN users u ON j.owner_id=u.id WHERE owner_id=? ORDER BY id DESC LIMIT 10", (current_user.id,))
    jobs = [dict(r) for r in c.fetchall()]
    if current_user.role == "admin":
        c.execute("SELECT recipient_to as to, status, sid, error FROM messages ORDER BY id DESC LIMIT 50")
    else:
        c.execute("SELECT recipient_to as to, status, sid, error FROM messages WHERE assigned_user_id=? OR assigned_user_id IS NULL ORDER BY id DESC LIMIT 50", (current_user.id,))
    recent = [dict(r) for r in c.fetchall()]
    conn.close()
    return render_template("index.html", jobs=jobs, recent=recent, webhook_url=PUBLIC_WEBHOOK_URL)

@app.route("/new")
@login_required
def new_campaign():
    conn = db(); c = conn.cursor()
    c.execute("SELECT id,email,role,created_at FROM users ORDER BY id ASC")
    users = [dict(r) for r in c.fetchall()]
    conn.close()
    return render_template("new_campaign.html", users=users, webhook_url=PUBLIC_WEBHOOK_URL)

@app.route("/create", methods=["POST"])
@login_required
def create_campaign():
    name = request.form.get("name")
    template = request.form.get("template")
    rate = int(request.form.get("rate") or 30)
    col_phone = request.form.get("col_phone") or "phone"
    col_name = request.form.get("col_name") or "name"
    col_company = request.form.get("col_company") or "company"
    assignment = request.form.get("assignment") or "none"
    selected = request.form.getlist("users")
    percent_json = request.form.get("percent_json","").strip()

    # pack assignment meta into name to keep schema simple
    meta = {"strategy": assignment, "user_ids": [int(x) for x in selected] if selected else []}
    if percent_json:
        try:
            perc = json.loads(percent_json)
            meta["percents"] = {int(k): float(v) for k,v in perc.items()}
        except Exception:
            pass
    name_meta = name + "::" + json.dumps(meta)

    file = request.files["csv"]
    filename = secure_filename(file.filename)
    path = os.path.join("uploads", f"{int(time.time())}_{filename}")
    file.save(path)

    conn = db(); c = conn.cursor()
    c.execute("""INSERT INTO jobs(name, template, col_phone, col_name, col_company, csv_path, rate, status, created_at, owner_id)
                 VALUES(?,?,?,?,?,?,?,?,datetime('now'),?)""",
              (name_meta, template, col_phone, col_name, col_company, path, rate, "pending", current_user.id))
    conn.commit(); job_id = c.lastrowid; conn.close()
    return redirect(url_for("job_detail", job_id=job_id))

@app.route("/jobs")
@login_required
def jobs():
    conn = db(); c = conn.cursor()
    if current_user.role == "admin":
        c.execute("SELECT j.*, u.email as owner_email FROM jobs j LEFT JOIN users u ON j.owner_id=u.id ORDER BY id DESC")
    else:
        c.execute("SELECT j.*, u.email as owner_email FROM jobs j LEFT JOIN users u ON j.owner_id=u.id WHERE owner_id=? ORDER BY id DESC", (current_user.id,))
    jobs = [dict(r) for r in c.fetchall()]
    conn.close()
    return render_template("jobs.html", jobs=jobs, webhook_url=PUBLIC_WEBHOOK_URL)

@app.route("/jobs/<int:job_id>")
@login_required
def job_detail(job_id):
    conn = db(); c = conn.cursor()
    c.execute("SELECT j.*, u.email as owner_email FROM jobs j LEFT JOIN users u ON j.owner_id=u.id WHERE j.id=?", (job_id,))
    job = dict(c.fetchone())
    if current_user.role != "admin" and job["owner_id"] != current_user.id:
        return redirect(url_for("jobs"))
    c.execute("""SELECT m.recipient_to as to, m.status, m.sid, m.error, COALESCE(u.email,'—') as user_email
                 FROM messages m LEFT JOIN users u ON u.id=m.assigned_user_id
                 WHERE m.job_id=? ORDER BY m.id DESC LIMIT 100""", (job_id,))
    recent = [dict(r) for r in c.fetchall()]
    conn.close()
    return render_template("job_detail.html", job=job, recent=recent, webhook_url=PUBLIC_WEBHOOK_URL)

@app.route("/jobs/<int:job_id>/status")
@login_required
def job_status(job_id):
    conn = db(); c = conn.cursor()
    c.execute("SELECT status, sent, total FROM jobs WHERE id=?", (job_id,))
    r = c.fetchone(); conn.close()
    return jsonify(dict(status=r["status"], sent=r["sent"], total=r["total"]))

@app.route("/jobs/<int:job_id>/start")
@login_required
@admin_required
def start_job(job_id):
    conn = db(); c = conn.cursor()
    c.execute("UPDATE jobs SET status='running' WHERE id=?", (job_id,))
    conn.commit(); conn.close()
    t = threading.Thread(target=send_worker, args=(job_id,), daemon=True)
    t.start(); return redirect(url_for("job_detail", job_id=job_id))

@app.route("/jobs/<int:job_id>/pause")
@login_required
@admin_required
def pause_job(job_id):
    conn = db(); c = conn.cursor()
    c.execute("UPDATE jobs SET status='paused' WHERE id=?", (job_id,))
    conn.commit(); conn.close()
    return redirect(url_for("job_detail", job_id=job_id))

@app.route("/jobs/<int:job_id>/download")
@login_required
def download_log(job_id):
    conn = db(); c = conn.cursor()
    c.execute("SELECT id, recipient_to, assigned_user_id, direction, status, sid, error, body, ts FROM messages WHERE job_id=? ORDER BY id ASC", (job_id,))
    rows = c.fetchall(); conn.close()
    out_path = os.path.join("data", f"log_job_{job_id}.csv")
    with open(out_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["id","to","assigned_user_id","direction","status","sid","error","body","timestamp"])
        for r in rows:
            w.writerow([r["id"], r["recipient_to"], r["assigned_user_id"], r["direction"], r["status"], r["sid"], r["error"], r["body"], r["ts"]])
    return send_file(out_path, as_attachment=True, download_name=f"log_job_{job_id}.csv")

@app.route("/messages")
@login_required
def messages():
    q = request.args.get("q","").strip()
    status = request.args.get("status","").strip()
    conn = db(); c = conn.cursor()
    base = "SELECT m.*, COALESCE(u.email,'—') as user_email FROM messages m LEFT JOIN users u ON u.id=m.assigned_user_id WHERE 1=1 "
    params = []
    if current_user.role != "admin":
        base += " AND (m.assigned_user_id=? OR m.assigned_user_id IS NULL)"; params.append(current_user.id)
    if status:
        base += " AND m.status=?"; params.append(status)
    if q:
        base += " AND (m.recipient_to LIKE ? OR m.body LIKE ?)"; params += [f"%{q}%", f"%{q}%"]
    base += " ORDER BY m.id DESC LIMIT 200"
    c.execute(base, params)
    rows = c.fetchall(); conn.close()

    items = []
    for r in rows:
        direction = r["direction"] or "outbound"
        peer = r["recipient_to"]
        ts_str = datetime.datetime.fromtimestamp(r["ts"]).strftime("%Y-%m-%d %H:%M:%S") if r["ts"] else ""
        items.append(dict(ts=ts_str, peer=peer, direction=direction, user_email=r["user_email"],
                          status=r["status"], snippet=(r["body"] or "")[:120]))
    return render_template("messages.html", items=items, q=q, status=status, webhook_url=PUBLIC_WEBHOOK_URL)

# Admin
@app.route("/admin/users")
@login_required
@admin_required
def admin_users():
    conn = db(); c = conn.cursor()
    c.execute("SELECT id,email,role,created_at FROM users ORDER BY id ASC")
    users = [dict(r) for r in c.fetchall()]; conn.close()
    return render_template("admin_users.html", users=users, webhook_url=PUBLIC_WEBHOOK_URL)

@app.route("/admin/users/add", methods=["POST"])
@login_required
@admin_required
def admin_users_add():
    email = request.form["email"].strip().lower()
    pw = request.form["password"]; role = request.form.get("role","user")
    hashed = bcrypt.generate_password_hash(pw).decode("utf-8")
    conn = db(); c = conn.cursor()
    try:
        c.execute("INSERT INTO users(email,password,role,created_at) VALUES(?,?,?,datetime('now'))",
                  (email, hashed, role)); conn.commit(); flash("User added")
    except Exception as e:
        flash(f"Error: {e}")
    finally:
        conn.close()
    return redirect(url_for("admin_users"))

@app.route("/admin/settings", methods=["GET","POST"])
@login_required
@admin_required
def admin_settings():
    if request.method == "POST":
        ghl_url = request.form.get("ghl_url","").strip()
        ghl_headers = request.form.get("ghl_headers","").strip()
        conn = db(); c = conn.cursor()
        c.execute("INSERT OR REPLACE INTO kv(key,value) VALUES('ghl_url',?)",(ghl_url,))
        c.execute("INSERT OR REPLACE INTO kv(key,value) VALUES('ghl_headers',?)",(ghl_headers,))
        conn.commit(); conn.close()
        flash("Saved"); return redirect(url_for("admin_settings"))
    conn = db(); c = conn.cursor()
    c.execute("SELECT key,value FROM kv WHERE key IN ('ghl_url','ghl_headers')")
    settings = {r["key"]: r["value"] for r in c.fetchall()}
    conn.close()
    return render_template("admin_settings.html", settings=settings, webhook_url=PUBLIC_WEBHOOK_URL)

# Inbound webhook
@app.post("/sms/inbound")
def sms_inbound():
    from_number = request.form.get("From","").strip()
    body = (request.form.get("Body","") or "").strip()
    low = body.lower()

    # STOP/HELP/START
    if low in ["stop","stopall","unsubscribe","cancel","end","quit"]:
        add_suppression(from_number)
        resp = """<?xml version="1.0" encoding="UTF-8"?><Response><Message>You’re opted out. No more texts. Reply START to opt back in.</Message></Response>"""
        status = "inbound"
    elif low in ["help","info"]:
        resp = """<?xml version="1.0" encoding="UTF-8"?><Response><Message>FundFlex Capital: Reply STOP to opt out. Msg&Data rates may apply.</Message></Response>"""
        status = "inbound"
    elif low.strip() == "start":
        remove_suppression(from_number)
        resp = """<?xml version="1.0" encoding="UTF-8"?><Response><Message>You’re opted back in. How can we help?</Message></Response>"""
        status = "inbound"
    else:
        resp = "" ; status = "inbound"

    # naive positive intent detection
    positive = any(p in low for p in ["yes","interested","call me","let's talk","we need","send info","how much","ready"])

    # log inbound
    conn = db(); c = conn.cursor()
    c.execute("INSERT INTO messages(job_id, recipient_to, assigned_user_id, direction, status, sid, error, body, ts) VALUES(?,?,?,?,?,?,?,?,?)",
              (None, from_number, None, "inbound", status, "", "", body, time.time()))
    conn.commit(); conn.close()

    # push to GHL if positive
    if positive:
        ok, info = push_to_ghl({"from": from_number, "body": body, "source": "twilio-sms-pro"})
        # optionally log push result
        conn = db(); c = conn.cursor()
        c.execute("INSERT INTO messages(job_id, recipient_to, assigned_user_id, direction, status, sid, error, body, ts) VALUES(?,?,?,?,?,?,?,?,?)",
                  (None, from_number, None, "system", "ghl_push", "", ("ok" if ok else f"fail:{info}"), body, time.time()))
        conn.commit(); conn.close()

    return (resp, 200, {"Content-Type": "text/xml"})

if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=True)

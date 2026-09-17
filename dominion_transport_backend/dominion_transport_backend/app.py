import os
import sqlite3
import re
from datetime import datetime
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, jsonify, send_from_directory, g
)

# ------------------------------------------------------------------
# CONFIG
# ------------------------------------------------------------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "dominion.db")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "pdf", "webp"}
MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5 MB

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.config["SECRET_KEY"] = "change-this-to-a-long-random-secret-key-please"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH


# ------------------------------------------------------------------
# ADMIN CREDENTIALS (change these!)
# ------------------------------------------------------------------
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD_HASH = generate_password_hash("dominion2025")


# ------------------------------------------------------------------
# DATABASE HELPERS
# ------------------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Create tables if they don't exist."""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # ---------- USERS ----------
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            firstname     TEXT NOT NULL,
            lastname      TEXT NOT NULL,
            username      TEXT NOT NULL UNIQUE,
            email         TEXT NOT NULL UNIQUE,
            dob           TEXT NOT NULL,
            nin           TEXT NOT NULL UNIQUE,
            nin_photo     TEXT,
            password_hash TEXT NOT NULL,
            created_at    TEXT NOT NULL
        )
    """)

    # ---------- BOOKINGS (with payment proof + status) ----------
    cur.execute("""
        CREATE TABLE IF NOT EXISTS bookings (
            id                 INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id            INTEGER,
            reference          TEXT NOT NULL UNIQUE,
            vehicle            TEXT NOT NULL,
            task               TEXT NOT NULL,
            other_task         TEXT,
            state              TEXT NOT NULL,
            vehicle_price      INTEGER NOT NULL,
            state_price        INTEGER NOT NULL,
            total_price        INTEGER NOT NULL,
            payment_bank       TEXT,
            payment_reference  TEXT,
            payment_receipt    TEXT,
            status             TEXT NOT NULL DEFAULT 'pending',
            admin_note         TEXT,
            created_at         TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)

    conn.commit()
    conn.close()


# ------------------------------------------------------------------
# LOGIN REQUIRED DECORATOR
# ------------------------------------------------------------------
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please sign in to continue.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


# ------------------------------------------------------------------
# ADMIN REQUIRED DECORATOR
# ------------------------------------------------------------------
def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("is_admin"):
            flash("Admin login required.", "warning")
            return redirect(url_for("admin_login"))
        return view(*args, **kwargs)
    return wrapped


# ------------------------------------------------------------------
# VALIDATION HELPERS
# ------------------------------------------------------------------
EMAIL_RE    = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.]{3,20}$")
NIN_RE      = re.compile(r"^\d{11}$")
ACCT_RE     = re.compile(r"^\d{10}$")


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


# ------------------------------------------------------------------
# DOMINION COMPANY BANK DETAILS
# ------------------------------------------------------------------
COMPANY_BANK = {
    "bank_name":      "Access Bank",
    "account_number": "0123456789",
    "account_name":   "Dominion Transport Solutions Ltd",
}


# ------------------------------------------------------------------
# PRICE TABLES (must match the HTML)
# ------------------------------------------------------------------
VEHICLE_PRICES = {
    "bike": 5000, "car": 10000, "suv": 15000, "van": 18000,
    "truck-small": 25000, "truck-large": 40000, "trailer": 60000,
}

STATE_PRICES = {
    "abia": 15000, "adamawa": 28000, "akwa-ibom": 22000, "anambra": 16000,
    "bauchi": 27000, "bayelsa": 23000, "benue": 24000, "borno": 35000,
    "cross-river": 21000, "delta": 17000, "ebonyi": 18000, "edo": 15000,
    "ekiti": 14000, "enugu": 16000, "fct": 10000, "gombe": 29000,
    "imo": 17000, "jigawa": 30000, "kaduna": 25000, "kano": 26000,
    "katsina": 29000, "kebbi": 31000, "kogi": 13000, "kwara": 14000,
    "lagos": 8000, "nasarawa": 20000, "niger": 22000, "ogun": 10000,
    "ondo": 13000, "osun": 14000, "oyo": 12000, "plateau": 25000,
    "rivers": 18000, "sokoto": 32000, "taraba": 29000, "yobe": 34000,
    "zamfara": 33000,
}

BANKS = [
    "access", "citibank", "ecobank", "fidelity", "fcmb", "firstbank",
    "gtbank", "heritage", "keystone", "kuda", "opay", "palmpay",
    "polaris", "providus", "stanbic", "standard", "sterling", "uba",
    "union", "unity", "wema", "zenith",
]


def generate_reference():
    """Return a unique booking reference like DOM-20250917-0001."""
    db = get_db()
    today = datetime.now().strftime("%Y%m%d")
    count = db.execute(
        "SELECT COUNT(*) FROM bookings WHERE reference LIKE ?",
        (f"DOM-{today}-%",)
    ).fetchone()[0]
    return f"DOM-{today}-{count + 1:04d}"


# ==================================================================
# PUBLIC ROUTES
# ==================================================================

# ---------- HOME / LANDING ----------
@app.route("/")
def home():
    return render_template("about_website.html")


# ---------- LOGIN (email OR username) ----------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        identifier = (request.form.get("identifier") or "").strip()
        password   = request.form.get("password") or ""

        if not identifier or not password:
            flash("Please enter your email/username and password.", "error")
            return redirect(url_for("login"))

        db = get_db()
        user = db.execute(
            """SELECT * FROM users
               WHERE LOWER(username) = LOWER(?)
                  OR LOWER(email)    = LOWER(?)""",
            (identifier, identifier),
        ).fetchone()

        if user is None:
            flash("No account found with that email or username.", "error")
            return redirect(url_for("login"))

        if not check_password_hash(user["password_hash"], password):
            flash("Incorrect password. Try again.", "error")
            return redirect(url_for("login"))

        session["user_id"]   = user["id"]
        session["username"]  = user["username"]
        session["user_name"] = f"{user['firstname']} {user['lastname']}"
        flash(f"Welcome back, {user['firstname']}!", "success")
        return redirect(url_for("dashboard"))

    return render_template("login.html")


# ---------- CREATE ACCOUNT ----------
@app.route("/create", methods=["GET", "POST"])
def create():
    if request.method == "POST":
        firstname = (request.form.get("firstname") or "").strip()
        lastname  = (request.form.get("lastname")  or "").strip()
        username  = (request.form.get("username")  or "").strip()
        email     = (request.form.get("email")     or "").strip().lower()
        dob       = (request.form.get("dob")       or "").strip()
        nin       = (request.form.get("nin")       or "").strip()
        password  = request.form.get("password") or ""

        # ---------- validation ----------
        errors = []
        if not firstname or not lastname:
            errors.append("First and last name are required.")
        if not USERNAME_RE.match(username):
            errors.append("Username must be 3–20 characters (letters, numbers, _ or .).")
        if not EMAIL_RE.match(email):
            errors.append("Please enter a valid email address.")
        if not dob:
            errors.append("Date of birth is required.")
        if not NIN_RE.match(nin):
            errors.append("NIN must be exactly 11 digits.")
        if len(password) < 6:
            errors.append("Password must be at least 6 characters.")

        # file upload
        file = request.files.get("nin_photo")
        saved_filename = None
        if not file or file.filename == "":
            errors.append("Please upload your NIN photo/slip.")
        elif not allowed_file(file.filename):
            errors.append("File type not allowed. Use JPG, PNG, or PDF.")

        if errors:
            for e in errors:
                flash(e, "error")
            return redirect(url_for("create"))

        # ---------- duplicate checks ----------
        db = get_db()
        if db.execute("SELECT 1 FROM users WHERE LOWER(username)=LOWER(?)", (username,)).fetchone():
            flash("That username is already taken. Please choose another.", "error")
            return redirect(url_for("create"))
        if db.execute("SELECT 1 FROM users WHERE LOWER(email)=LOWER(?)", (email,)).fetchone():
            flash("An account with that email already exists.", "error")
            return redirect(url_for("create"))
        if db.execute("SELECT 1 FROM users WHERE nin=?", (nin,)).fetchone():
            flash("An account with that NIN already exists.", "error")
            return redirect(url_for("create"))

        # ---------- save NIN photo ----------
        original  = secure_filename(file.filename)
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        saved_filename = f"{nin}_{timestamp}_{original}"
        file.save(os.path.join(app.config["UPLOAD_FOLDER"], saved_filename))

        # ---------- insert user ----------
        try:
            db.execute(
                """INSERT INTO users
                   (firstname, lastname, username, email, dob, nin,
                    nin_photo, password_hash, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    firstname, lastname, username, email, dob, nin,
                    saved_filename,
                    generate_password_hash(password),
                    datetime.now().isoformat(timespec="seconds"),
                ),
            )
            db.commit()
        except sqlite3.IntegrityError as ex:
            flash(f"Could not create account: {ex}", "error")
            return redirect(url_for("create"))

        flash("Account created successfully. Please sign in.", "success")
        return redirect(url_for("login"))

    return render_template("create.html")


# ---------- LOGOUT ----------
@app.route("/logout")
def logout():
    session.clear()
    flash("You have been signed out.", "info")
    return redirect(url_for("login"))


# ---------- DASHBOARD ----------
@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    bookings = db.execute(
        "SELECT * FROM bookings WHERE user_id=? ORDER BY id DESC",
        (session["user_id"],),
    ).fetchall()
    return render_template(
        "dashbord.html",
        user=user,
        bookings=bookings,
        company_bank=COMPANY_BANK,
    )


# ---------- BOOKING API (AJAX — multipart because of receipt) ----------
@app.route("/api/book", methods=["POST"])
@login_required
def api_book():
    vehicle        = (request.form.get("vehicle") or "").strip()
    task           = (request.form.get("task") or "").strip()
    other_task     = (request.form.get("otherTask") or "").strip()
    state          = (request.form.get("state") or "").strip()
    payment_bank   = (request.form.get("paymentBank") or "").strip()
    payment_ref    = (request.form.get("paymentReference") or "").strip()

    # ---------- validation ----------
    if vehicle not in VEHICLE_PRICES:
        return jsonify(ok=False, error="Invalid vehicle type."), 400
    if task not in ("ride", "waybill", "transfer", "other"):
        return jsonify(ok=False, error="Invalid task type."), 400
    if task == "other" and not other_task:
        return jsonify(ok=False, error="Please describe your custom task."), 400
    if state not in STATE_PRICES:
        return jsonify(ok=False, error="Invalid state."), 400
    if payment_bank not in BANKS:
        return jsonify(ok=False, error="Please select the bank you paid from."), 400
    if not payment_ref:
        return jsonify(ok=False, error="Please enter your payment reference."), 400

    receipt = request.files.get("paymentReceipt")
    if not receipt or receipt.filename == "":
        return jsonify(ok=False, error="Please upload your payment receipt."), 400
    if not allowed_file(receipt.filename):
        return jsonify(ok=False, error="Receipt must be JPG, PNG, or PDF."), 400

    vehicle_price = VEHICLE_PRICES[vehicle]
    state_price   = STATE_PRICES[state]
    total_price   = vehicle_price + state_price
    reference     = generate_reference()

    # ---------- save the receipt ----------
    original  = secure_filename(receipt.filename)
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    saved_receipt = f"receipt_{reference}_{timestamp}_{original}"
    receipt.save(os.path.join(app.config["UPLOAD_FOLDER"], saved_receipt))

    # ---------- insert booking ----------
    db = get_db()
    db.execute(
        """INSERT INTO bookings
           (user_id, reference, vehicle, task, other_task, state,
            vehicle_price, state_price, total_price,
            payment_bank, payment_reference, payment_receipt,
            status, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            session["user_id"], reference, vehicle, task, other_task or None, state,
            vehicle_price, state_price, total_price,
            payment_bank, payment_ref, saved_receipt,
            "pending",
            datetime.now().isoformat(timespec="seconds"),
        ),
    )
    db.commit()

    return jsonify(
        ok=True,
        reference=reference,
        total=total_price,
        status="pending",
        message=(
            f"Booking {reference} submitted for verification. "
            "We'll confirm once we receive your payment."
        ),
    )


# ---------- LIST BOOKINGS (JSON, for auto-refresh) ----------
@app.route("/api/bookings")
@login_required
def api_bookings():
    db = get_db()
    rows = db.execute(
        """SELECT reference, vehicle, task, other_task, state,
                  total_price, status, created_at
           FROM bookings WHERE user_id=? ORDER BY id DESC""",
        (session["user_id"],),
    ).fetchall()
    return jsonify(ok=True, bookings=[dict(r) for r in rows])


# ---------- SERVE UPLOADED FILES ----------
@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


# ==================================================================
# ADMIN ROUTES
# ==================================================================

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = (request.form.get("password") or "")

        if username != ADMIN_USERNAME or not check_password_hash(ADMIN_PASSWORD_HASH, password):
            flash("Invalid admin credentials.", "error")
            return redirect(url_for("admin_login"))

        session["is_admin"] = True
        session["admin_username"] = username
        flash("Welcome, admin.", "success")
        return redirect(url_for("admin_dashboard"))

    return render_template("admin_login.html")


@app.route("/admin/logout")
def admin_logout():
    session.pop("is_admin", None)
    session.pop("admin_username", None)
    flash("Admin signed out.", "info")
    return redirect(url_for("admin_login"))


@app.route("/admin")
@admin_required
def admin_dashboard():
    status_filter = request.args.get("status", "all")
    db = get_db()

    if status_filter == "all":
        rows = db.execute(
            """SELECT b.*, u.firstname, u.lastname, u.username, u.email
               FROM bookings b LEFT JOIN users u ON u.id = b.user_id
               ORDER BY b.id DESC"""
        ).fetchall()
    else:
        rows = db.execute(
            """SELECT b.*, u.firstname, u.lastname, u.username, u.email
               FROM bookings b LEFT JOIN users u ON u.id = b.user_id
               WHERE b.status = ?
               ORDER BY b.id DESC""",
            (status_filter,),
        ).fetchall()

    counts = {
        "all":      db.execute("SELECT COUNT(*) FROM bookings").fetchone()[0],
        "pending":  db.execute("SELECT COUNT(*) FROM bookings WHERE status='pending'").fetchone()[0],
        "approved": db.execute("SELECT COUNT(*) FROM bookings WHERE status='approved'").fetchone()[0],
        "rejected": db.execute("SELECT COUNT(*) FROM bookings WHERE status='rejected'").fetchone()[0],
    }

    return render_template(
        "admin.html",
        bookings=rows,
        counts=counts,
        status_filter=status_filter,
        admin_username=session.get("admin_username"),
    )


@app.route("/admin/booking/<reference>")
@admin_required
def admin_booking_detail(reference):
    db = get_db()
    row = db.execute(
        """SELECT b.*, u.firstname, u.lastname, u.username, u.email, u.nin, u.dob
           FROM bookings b LEFT JOIN users u ON u.id = b.user_id
           WHERE b.reference = ?""",
        (reference,),
    ).fetchone()

    if row is None:
        flash("Booking not found.", "error")
        return redirect(url_for("admin_dashboard"))

    return render_template("admin_booking.html", b=row)


@app.route("/admin/action", methods=["POST"])
@admin_required
def admin_action():
    reference = (request.form.get("reference") or "").strip()
    action    = (request.form.get("action") or "").strip()
    note      = (request.form.get("note") or "").strip()

    if action not in ("approve", "reject"):
        flash("Invalid action.", "error")
        return redirect(url_for("admin_dashboard"))

    new_status = "approved" if action == "approve" else "rejected"

    db = get_db()
    row = db.execute("SELECT id FROM bookings WHERE reference=?", (reference,)).fetchone()
    if row is None:
        flash("Booking not found.", "error")
        return redirect(url_for("admin_dashboard"))

    db.execute(
        "UPDATE bookings SET status=?, admin_note=? WHERE reference=?",
        (new_status, note or None, reference),
    )
    db.commit()

    flash(f"Booking {reference} marked as {new_status.upper()}.", "success")
    return redirect(url_for("admin_booking_detail", reference=reference))


# ------------------------------------------------------------------
# ENTRY POINT
# ------------------------------------------------------------------
if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="0.0.0.0", port=5000)
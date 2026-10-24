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

# ---------- Brevo SDK ----------
from brevo import Brevo
from brevo.transactional_emails import SendTransacEmailRequestSender, SendTransacEmailRequestToItem

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
# ADMIN CREDENTIALS
# ------------------------------------------------------------------
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD_HASH = generate_password_hash("dominion2025")

# ------------------------------------------------------------------
# EMAIL CONFIG (Brevo)
# ------------------------------------------------------------------
BREVO_API_KEY = os.environ.get("BREVO_API_KEY")
EMAIL_FROM    = os.environ.get("EMAIL_FROM", "onboarding@resend.dev")
COMPANY_NAME  = "Dominion Transport Solutions"

# Initialize the Brevo client if the key exists
brevo_client = None
if BREVO_API_KEY:
    brevo_client = Brevo(api_key=BREVO_API_KEY)
else:
    print("[email] Warning: BREVO_API_KEY is not set. Emails will not be sent.")


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
    """Create tables and handle migrations."""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

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

    # ---------- MIGRATION FIX: REBUILD BOOKINGS TABLE ----------
    cur.execute("PRAGMA table_info(bookings)")
    cols = cur.fetchall()
    
    if cols:
        col_names = [c[1] for c in cols]
        if "state" in col_names:
            print("[init_db] Old 'state' column detected. Rebuilding bookings table...")
            cur.execute("ALTER TABLE bookings RENAME TO bookings_old")
            
            cur.execute("""
                CREATE TABLE bookings (
                    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id            INTEGER,
                    reference          TEXT NOT NULL UNIQUE,
                    vehicle            TEXT NOT NULL,
                    task               TEXT NOT NULL,
                    other_task         TEXT,
                    pickup_state       TEXT,
                    pickup_city        TEXT,
                    pickup_address     TEXT,
                    pickup_contact     TEXT,
                    pickup_phone       TEXT,
                    dropoff_state      TEXT,
                    dropoff_city       TEXT,
                    dropoff_address    TEXT,
                    dropoff_contact    TEXT,
                    dropoff_phone      TEXT,
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
            
            cur.execute("""
                INSERT INTO bookings (
                    id, user_id, reference, vehicle, task, other_task,
                    pickup_state, pickup_city, pickup_address, pickup_contact, pickup_phone,
                    dropoff_state, dropoff_city, dropoff_address, dropoff_contact, dropoff_phone,
                    vehicle_price, state_price, total_price,
                    payment_bank, payment_reference, payment_receipt,
                    status, admin_note, created_at
                )
                SELECT 
                    id, user_id, reference, vehicle, task, other_task,
                    NULL, NULL, NULL, NULL, NULL,
                    state, NULL, NULL, NULL, NULL,
                    vehicle_price, state_price, total_price,
                    payment_bank, payment_reference, payment_receipt,
                    status, admin_note, created_at
                FROM bookings_old
            """)
            
            cur.execute("DROP TABLE bookings_old")
            print("[init_db] Migration complete. Old data preserved.")

    cur.execute("""
        CREATE TABLE IF NOT EXISTS bookings (
            id                 INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id            INTEGER,
            reference          TEXT NOT NULL UNIQUE,
            vehicle            TEXT NOT NULL,
            task               TEXT NOT NULL,
            other_task         TEXT,
            pickup_state       TEXT,
            pickup_city        TEXT,
            pickup_address     TEXT,
            pickup_contact     TEXT,
            pickup_phone       TEXT,
            dropoff_state      TEXT,
            dropoff_city       TEXT,
            dropoff_address    TEXT,
            dropoff_contact    TEXT,
            dropoff_phone      TEXT,
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


with app.app_context():
    try:
        init_db()
    except Exception as _e:
        print(f"[init_db] startup migration failed: {_e}")


# ------------------------------------------------------------------
# DECORATORS
# ------------------------------------------------------------------
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please sign in to continue.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped

def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("is_admin"):
            flash("Admin login required.", "warning")
            return redirect(url_for("admin_login"))
        return view(*args, **kwargs)
    return wrapped

# ------------------------------------------------------------------
# VALIDATION & EMAIL HELPERS
# ------------------------------------------------------------------
EMAIL_RE    = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.]{3,20}$")
NIN_RE      = re.compile(r"^\d{11}$")

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


# ---------- EMAIL HTML WRAPPER ----------
def get_email_template(title, body_html):
    """Wraps the email content in a beautiful Dominion Transport HTML layout."""
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <style>
        body {{ font-family: 'Inter', Arial, sans-serif; background-color: #f4f7fa; margin: 0; padding: 0; color: #0b2a3b; }}
        .container {{ max-width: 600px; margin: 40px auto; background-color: #ffffff; border-radius: 16px; overflow: hidden; box-shadow: 0 10px 30px rgba(10, 42, 59, 0.1); }}
        .header {{ background-color: #0a2a3b; padding: 30px 20px; text-align: center; color: #ffffff; }}
        .header h1 {{ margin: 0; font-size: 24px; font-weight: 700; }}
        .header span {{ font-weight: 300; color: #7dc9f0; }}
        .content {{ padding: 30px 40px; line-height: 1.6; font-size: 15px; }}
        .footer {{ background-color: #f4f7fa; padding: 20px; text-align: center; font-size: 12px; color: #839eae; }}
        .btn {{ display: inline-block; padding: 12px 24px; background-color: #2d9cdb; color: #ffffff; text-decoration: none; border-radius: 30px; font-weight: bold; margin-top: 20px; }}
        .details-table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        .details-table td {{ padding: 10px; border-bottom: 1px solid #e2edf5; }}
        .details-table td:first-child {{ color: #5e7a8c; font-weight: 600; }}
        .details-table td:last-child {{ text-align: right; font-weight: 700; }}
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1>Dominion <span>Transport</span></h1>
          <p style="margin: 5px 0 0 0; font-size: 14px; opacity: 0.8;">{title}</p>
        </div>
        <div class="content">
          {body_html}
        </div>
        <div class="footer">
          &copy; {datetime.now().year} Dominion Transport Solutions. All rights reserved.<br>
          This is an automated message, please do not reply.
        </div>
      </div>
    </body>
    </html>
    """

# ---------- BREVO EMAIL SENDER ----------
def send_email(to_email, subject, body_html):
    """Send an email using Brevo API. Returns True on success."""
    if not brevo_client:
        print("[email] Brevo client not initialized — skipping.")
        return False

    try:
        brevo_client.transactional_emails.send_transac_email(
            subject=subject,
            html_content=body_html,
            sender=SendTransacEmailRequestSender(
                email=EMAIL_FROM,
                name=COMPANY_NAME
            ),
            to=[SendTransacEmailRequestToItem(email=to_email)]
        )
        print(f"[email] Sent to {to_email}: {subject}")
        return True

    except Exception as e:
        print(f"[email] Failed to send to {to_email}: {type(e).__name__} — {e}")
        return False


def send_welcome_email(to_email, firstname, username):
    subject = f"Welcome to {COMPANY_NAME}! 🚀"
    body = f"""
        <h2 style="color: #0a2a3b; margin-top: 0;">Hello {firstname}, 👋</h2>
        <p>Welcome to <strong>{COMPANY_NAME}</strong>! We are thrilled to have you on board.</p>
        <p>Your account has been successfully created. You can now book rides, send waybills, and transfer goods across Nigeria with ease.</p>
        <p>Here are your account details:</p>
        <table class="details-table">
            <tr><td>Username</td><td>@{username}</td></tr>
            <tr><td>Email</td><td>{to_email}</td></tr>
        </table>
        <p>Ready to get started? Click the button below to sign in and make your first booking.</p>
        <div style="text-align: center;">
            <a href="https://transport-app-pnco.onrender.com/login" class="btn">Sign In to Your Account</a>
        </div>
        <p style="margin-top: 30px;">Best regards,<br>The Dominion Transport Team</p>
    """
    send_email(to_email, subject, get_email_template("Welcome Aboard", body))


def send_booking_received_email(to_email, firstname, reference, total_price, pickup, dropoff):
    subject = f"Booking Received — {reference}"
    body = f"""
        <h2 style="color: #0a2a3b; margin-top: 0;">Hi {firstname},</h2>
        <p>Thank you for choosing Dominion Transport. We have successfully received your booking and your payment receipt is currently under review.</p>
        <p>Here is a summary of your request:</p>
        <table class="details-table">
            <tr><td>Reference</td><td>{reference}</td></tr>
            <tr><td>Amount Paid</td><td>₦{total_price:,}</td></tr>
            <tr><td>Pickup</td><td>{pickup}</td></tr>
            <tr><td>Drop-off</td><td>{dropoff}</td></tr>
            <tr><td>Status</td><td><span style="color: #f59e0b; font-weight: bold;">PENDING APPROVAL</span></td></tr>
        </table>
        <p>Our team will verify your payment shortly. Once approved, a driver will be assigned to your trip and you will receive another email.</p>
        <p>If you have any questions, feel free to reach out to our support team.</p>
        <p style="margin-top: 30px;">Safe travels,<br>The Dominion Transport Team</p>
    """
    send_email(to_email, subject, get_email_template("Booking Confirmation", body))


def send_booking_status_email(to_email, firstname, reference, total, status, note=None):
    if status == "approved":
        subject = f"Booking Approved ✓ — {reference}"
        body = f"""
            <h2 style="color: #16a34a; margin-top: 0;">Great news, {firstname}! 🎉</h2>
            <p>Your booking <strong>{reference}</strong> has been officially <strong>APPROVED</strong>.</p>
            <p>Our logistics team is currently assigning a vehicle to your request. A driver will contact you shortly using the phone number provided in your booking.</p>
            <table class="details-table">
                <tr><td>Reference</td><td>{reference}</td></tr>
                <tr><td>Amount Confirmed</td><td>₦{total:,}</td></tr>
                <tr><td>Status</td><td><span style="color: #16a34a; font-weight: bold;">APPROVED</span></td></tr>
            </table>
            <p>Thank you for trusting us with your logistics needs.</p>
        """
    else:
        subject = f"Booking Update — {reference}"
        reason = note or "No specific reason provided."
        body = f"""
            <h2 style="color: #dc2626; margin-top: 0;">Update on your booking</h2>
            <p>Hi {firstname},</p>
            <p>Unfortunately, we were unable to approve your booking <strong>{reference}</strong> at this time.</p>
            <table class="details-table">
                <tr><td>Reference</td><td>{reference}</td></tr>
                <tr><td>Status</td><td><span style="color: #dc2626; font-weight: bold;">REJECTED</span></td></tr>
                <tr><td>Reason</td><td>{reason}</td></tr>
            </table>
            <p>If you believe this is an error or if you'd like to make a new booking with corrected details, please sign in to your dashboard and try again.</p>
            <div style="text-align: center;">
                <a href="https://transport-app-pnco.onrender.com/login" class="btn">Go to Dashboard</a>
            </div>
        """
    send_email(to_email, subject, get_email_template("Booking Status Update", body))


def send_admin_new_booking_email(reference, user_name, user_email, vehicle, task, pickup, dropoff, total):
    admin_email = os.environ.get("GMAIL_USER", EMAIL_FROM)
    subject = f"🔔 New Booking Alert — {reference}"
    body = f"""
        <h2 style="color: #0a2a3b; margin-top: 0;">New Booking Received</h2>
        <p>A customer has just submitted a new booking with payment proof. Please log in to the admin dashboard to verify the receipt.</p>
        <table class="details-table">
            <tr><td>Reference</td><td>{reference}</td></tr>
            <tr><td>Customer</td><td>{user_name} ({user_email})</td></tr>
            <tr><td>Vehicle</td><td>{vehicle}</td></tr>
            <tr><td>Task</td><td>{task}</td></tr>
            <tr><td>Pickup</td><td>{pickup}</td></tr>
            <tr><td>Drop-off</td><td>{dropoff}</td></tr>
            <tr><td>Amount</td><td>₦{total:,}</td></tr>
        </table>
        <div style="text-align: center;">
            <a href="https://transport-app-pnco.onrender.com/admin" class="btn">Open Admin Dashboard</a>
        </div>
    """
    send_email(admin_email, subject, get_email_template("Admin Alert", body))

# ------------------------------------------------------------------
# PRICES & CONSTANTS
# ------------------------------------------------------------------
COMPANY_BANK = {"bank_name": "Fidelity Bank", "account_number": "6153338187", "account_name": "Doinion Enenche"}

VEHICLE_PRICES = {"bike": 5000, "car": 10000, "suv": 15000, "van": 18000, "truck-small": 25000, "truck-large": 40000, "trailer": 60000}

STATE_PRICES = {
    "abia": 15000, "adamawa": 28000, "akwa-ibom": 22000, "anambra": 16000, "bauchi": 27000,
    "bayelsa": 23000, "benue": 24000, "borno": 35000, "cross-river": 21000, "delta": 17000,
    "ebonyi": 18000, "edo": 15000, "ekiti": 14000, "enugu": 16000, "fct": 10000, "gombe": 29000,
    "imo": 17000, "jigawa": 30000, "kaduna": 25000, "kano": 26000, "katsina": 29000, "kebbi": 31000,
    "kogi": 13000, "kwara": 14000, "lagos": 8000, "nasarawa": 20000, "niger": 22000, "ogun": 10000,
    "ondo": 13000, "osun": 14000, "oyo": 12000, "plateau": 25000, "rivers": 18000, "sokoto": 32000,
    "taraba": 29000, "yobe": 34000, "zamfara": 33000
}

BANKS = ["access", "citibank", "ecobank", "fidelity", "fcmb", "firstbank", "gtbank", "heritage", "keystone", "kuda", "opay", "palmpay", "polaris", "providus", "stanbic", "standard", "sterling", "uba", "union", "unity", "wema", "zenith"]

def generate_reference():
    db = get_db()
    today = datetime.now().strftime("%Y%m%d")
    count = db.execute("SELECT COUNT(*) FROM bookings WHERE reference LIKE ?", (f"DOM-{today}-%",)).fetchone()[0]
    return f"DOM-{today}-{count + 1:04d}"

# ==================================================================
# ROUTES
# ==================================================================

@app.route("/")
def home():
    return render_template("about_website.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        identifier = (request.form.get("identifier") or "").strip()
        password   = (request.form.get("password") or "")
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE LOWER(username)=LOWER(?) OR LOWER(email)=LOWER(?)", (identifier, identifier)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session["user_id"]   = user["id"]
            session["username"]  = user["username"]
            session["user_name"] = f"{user['firstname']} {user['lastname']}"
            return redirect(url_for("dashboard"))
        flash("Invalid credentials.", "error")
    return render_template("login.html")

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

        if not all([firstname, lastname, username, email, dob, nin, password]):
            flash("All fields are required.", "error")
            return redirect(url_for("create"))

        file = request.files.get("nin_photo")
        if not file or not allowed_file(file.filename):
            flash("Valid NIN photo required.", "error")
            return redirect(url_for("create"))

        db = get_db()
        try:
            original  = secure_filename(file.filename)
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            saved_filename = f"{nin}_{timestamp}_{original}"
            file.save(os.path.join(app.config["UPLOAD_FOLDER"], saved_filename))
            
            db.execute(
                "INSERT INTO users (firstname, lastname, username, email, dob, nin, nin_photo, password_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (firstname, lastname, username, email, dob, nin, saved_filename, generate_password_hash(password), datetime.now().isoformat(timespec="seconds"))
            )
            db.commit()

            # Send Welcome Email
            send_welcome_email(email, firstname, username)

            flash("Account created! Please sign in.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username, Email, or NIN already exists.", "error")
            return redirect(url_for("create"))
    return render_template("create.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    bookings = db.execute("SELECT * FROM bookings WHERE user_id=? ORDER BY id DESC", (session["user_id"],)).fetchall()
    return render_template("dashbord.html", user=user, bookings=bookings, company_bank=COMPANY_BANK)

@app.route("/api/book", methods=["POST"])
@login_required
def api_book():
    try:
        vehicle    = (request.form.get("vehicle") or "").strip()
        task       = (request.form.get("task") or "").strip()
        other_task = (request.form.get("otherTask") or "").strip()

        pickup_state   = (request.form.get("pickupState")   or "").strip()
        pickup_city    = (request.form.get("pickupCity")    or "").strip()
        pickup_address = (request.form.get("pickupAddress") or "").strip()
        pickup_contact = (request.form.get("pickupContact") or "").strip()
        pickup_phone   = (request.form.get("pickupPhone")   or "").strip()

        dropoff_state   = (request.form.get("dropoffState")   or "").strip()
        dropoff_city    = (request.form.get("dropoffCity")    or "").strip()
        dropoff_address = (request.form.get("dropoffAddress") or "").strip()
        dropoff_contact = (request.form.get("dropoffContact") or "").strip()
        dropoff_phone   = (request.form.get("dropoffPhone")   or "").strip()

        payment_bank = (request.form.get("paymentBank") or "").strip()
        payment_ref  = (request.form.get("paymentReference") or "").strip()

        if vehicle not in VEHICLE_PRICES: return jsonify(ok=False, error="Invalid vehicle."), 400
        if pickup_state not in STATE_PRICES: return jsonify(ok=False, error="Invalid pickup state."), 400
        if dropoff_state not in STATE_PRICES: return jsonify(ok=False, error="Invalid dropoff state."), 400
        if not all([pickup_city, pickup_address, pickup_contact, pickup_phone]): return jsonify(ok=False, error="Missing pickup details."), 400
        if not all([dropoff_city, dropoff_address, dropoff_contact, dropoff_phone]): return jsonify(ok=False, error="Missing dropoff details."), 400
        if not payment_ref: return jsonify(ok=False, error="Missing payment reference."), 400

        receipt = request.files.get("paymentReceipt")
        if not receipt or not allowed_file(receipt.filename):
            return jsonify(ok=False, error="Valid receipt required."), 400

        vehicle_price = VEHICLE_PRICES[vehicle]
        state_price   = max(STATE_PRICES[pickup_state], STATE_PRICES[dropoff_state])
        total_price   = vehicle_price + state_price
        reference     = generate_reference()

        original  = secure_filename(receipt.filename)
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        saved_receipt = f"receipt_{reference}_{timestamp}_{original}"
        receipt.save(os.path.join(app.config["UPLOAD_FOLDER"], saved_receipt))

        db = get_db()
        db.execute(
            """INSERT INTO bookings
               (user_id, reference, vehicle, task, other_task,
                pickup_state, pickup_city, pickup_address, pickup_contact, pickup_phone,
                dropoff_state, dropoff_city, dropoff_address, dropoff_contact, dropoff_phone,
                vehicle_price, state_price, total_price,
                payment_bank, payment_reference, payment_receipt, status, created_at)
               VALUES (?, ?, ?, ?, ?,  ?, ?, ?, ?, ?,  ?, ?, ?, ?, ?,  ?, ?, ?,  ?, ?, ?,  ?, ?)""",
            (
                session["user_id"], reference, vehicle, task, other_task or None,
                pickup_state, pickup_city, pickup_address, pickup_contact, pickup_phone,
                dropoff_state, dropoff_city, dropoff_address, dropoff_contact, dropoff_phone,
                vehicle_price, state_price, total_price,
                payment_bank, payment_ref, saved_receipt, "pending",
                datetime.now().isoformat(timespec="seconds"),
            ),
        )
        db.commit()

        # Send booking received emails
        user_row = db.execute("SELECT email, firstname FROM users WHERE id=?", (session["user_id"],)).fetchone()
        if user_row:
            send_booking_received_email(
                user_row["email"], user_row["firstname"], reference, total_price,
                f"{pickup_state} ({pickup_city})", f"{dropoff_state} ({dropoff_city})"
            )
            send_admin_new_booking_email(
                reference, session.get("user_name"), user_row["email"], 
                vehicle, task, f"{pickup_state}-{pickup_city}", f"{dropoff_state}-{dropoff_city}", total_price
            )

        return jsonify(ok=True, reference=reference, message="Booking submitted.")
    except Exception as e:
        import traceback
        print(f"[api_book] FATAL: {e}\n{traceback.format_exc()}")
        return jsonify(ok=False, error=f"Server error: {str(e)}"), 500

@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)

# ==================================================================
# ADMIN ROUTES
# ==================================================================

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        if request.form.get("username") == ADMIN_USERNAME and check_password_hash(ADMIN_PASSWORD_HASH, request.form.get("password")):
            session["is_admin"] = True
            session["admin_username"] = ADMIN_USERNAME
            return redirect(url_for("admin_dashboard"))
        flash("Invalid admin credentials.", "error")
    return render_template("admin_login.html")

@app.route("/admin/logout")
def admin_logout():
    session.clear()
    return redirect(url_for("admin_login"))

@app.route("/admin")
@admin_required
def admin_dashboard():
    status_filter = request.args.get("status", "all")
    db = get_db()
    if status_filter == "all":
        rows = db.execute("SELECT b.*, u.firstname, u.lastname, u.username, u.email FROM bookings b LEFT JOIN users u ON u.id = b.user_id ORDER BY b.id DESC").fetchall()
    else:
        rows = db.execute("SELECT b.*, u.firstname, u.lastname, u.username, u.email FROM bookings b LEFT JOIN users u ON u.id = b.user_id WHERE b.status = ? ORDER BY b.id DESC", (status_filter,)).fetchall()

    counts = {
        "all": db.execute("SELECT COUNT(*) FROM bookings").fetchone()[0],
        "pending": db.execute("SELECT COUNT(*) FROM bookings WHERE status='pending'").fetchone()[0],
        "approved": db.execute("SELECT COUNT(*) FROM bookings WHERE status='approved'").fetchone()[0],
        "rejected": db.execute("SELECT COUNT(*) FROM bookings WHERE status='rejected'").fetchone()[0],
    }
    return render_template("admin.html", bookings=rows, counts=counts, status_filter=status_filter, admin_username=session.get("admin_username"))

@app.route("/admin/booking/<reference>")
@admin_required
def admin_booking_detail(reference):
    db = get_db()
    row = db.execute("SELECT b.*, u.firstname, u.lastname, u.username, u.email, u.nin, u.dob FROM bookings b LEFT JOIN users u ON u.id = b.user_id WHERE b.reference = ?", (reference,)).fetchone()
    if not row:
        return redirect(url_for("admin_dashboard"))
    row_dict = dict(row)
    for k in ["pickup_state", "pickup_city", "pickup_address", "pickup_contact", "pickup_phone", "dropoff_state", "dropoff_city", "dropoff_address", "dropoff_contact", "dropoff_phone"]:
        row_dict.setdefault(k, None)
    return render_template("admin_booking.html", b=row_dict)

@app.route("/admin/action", methods=["POST"])
@admin_required
def admin_action():
    reference = request.form.get("reference")
    action = request.form.get("action")
    note = request.form.get("note")
    
    new_status = "approved" if action == "approve" else "rejected"
    db = get_db()
    db.execute("UPDATE bookings SET status=?, admin_note=? WHERE reference=?", (new_status, note, reference))
    db.commit()

    user_row = db.execute("SELECT u.email, u.firstname, b.total_price FROM bookings b JOIN users u ON u.id = b.user_id WHERE b.reference = ?", (reference,)).fetchone()
    if user_row:
        send_booking_status_email(user_row["email"], user_row["firstname"], reference, user_row["total_price"], new_status, note)

    flash(f"Booking {reference} marked as {new_status.upper()}.", "success")
    return redirect(url_for("admin_booking_detail", reference=reference))

if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="0.0.0.0", port=5000)
    
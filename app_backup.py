import os
import re
import sqlite3
from datetime import datetime
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, g, send_from_directory, abort
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY", "local-demo-change-before-deployment"
)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE_DIR, "healthcare.db")
UPLOAD_DIR = os.path.join(BASE_DIR, "private_uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

ALLOWED_EXTENSIONS = {"pdf", "png", "jpg", "jpeg"}
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "admin@healthcare.com").lower()
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "Admin@12345")


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db


@app.teardown_appcontext
def close_db(error=None):
    db = g.pop("db", None)
    if db:
        db.close()


def init_db():
    db = get_db()

    # Users: admin, doctor and patient accounts
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            phone TEXT,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin', 'doctor', 'patient')),
            specialization TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Patient-doctor assignments
    db.execute("""
        CREATE TABLE IF NOT EXISTS patient_doctor (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id INTEGER NOT NULL,
            doctor_id INTEGER NOT NULL,
            assigned_at TEXT DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(patient_id, doctor_id),
            FOREIGN KEY(patient_id) REFERENCES users(id),
            FOREIGN KEY(doctor_id) REFERENCES users(id)
        )
    """)

    # Appointments
    db.execute("""
        CREATE TABLE IF NOT EXISTS appointments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id INTEGER NOT NULL,
            doctor_id INTEGER NOT NULL,
            appointment_date TEXT NOT NULL,
            reason TEXT,
            status TEXT NOT NULL DEFAULT 'Pending',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(patient_id) REFERENCES users(id),
            FOREIGN KEY(doctor_id) REFERENCES users(id)
        )
    """)

    # Medical reports and X-rays
    db.execute("""
        CREATE TABLE IF NOT EXISTS medical_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id INTEGER NOT NULL,
            uploaded_by INTEGER,
            title TEXT NOT NULL,
            file_name TEXT NOT NULL,
            file_type TEXT NOT NULL,
            uploaded_at TEXT NOT NULL,
            FOREIGN KEY(patient_id) REFERENCES users(id),
            FOREIGN KEY(uploaded_by) REFERENCES users(id)
        )
    """)

    # Migrate existing databases without deleting existing records.
    user_columns = {
        row["name"]
        for row in db.execute("PRAGMA table_info(users)").fetchall()
    }

    if "specialization" not in user_columns:
        db.execute("ALTER TABLE users ADD COLUMN specialization TEXT")

    file_columns = {
        row["name"]
        for row in db.execute("PRAGMA table_info(medical_files)").fetchall()
    }

    if "uploaded_by" not in file_columns:
        db.execute("ALTER TABLE medical_files ADD COLUMN uploaded_by INTEGER")

    db.commit()

def strong_password(password):
    return (
        len(password) >= 8
        and bool(re.search(r"[A-Z]", password))
        and bool(re.search(r"[a-z]", password))
        and bool(re.search(r"\d", password))
        and bool(re.search(r"[^A-Za-z0-9]", password))
    )


def login_required(role=None):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if "user_id" not in session:
                flash("Please login first.", "warning")
                return redirect(url_for("login"))

            if role and session.get("role") != role:
                flash("You are not authorized to open that page.", "danger")
                return redirect(url_for("dashboard"))

            return view(*args, **kwargs)
        return wrapped
    return decorator


@app.route("/")
def index():
    if session.get("role") == "admin":
        return redirect(url_for("admin_dashboard"))
    if session.get("role") == "doctor":
        return redirect(url_for("doctor_dashboard"))
    if session.get("role") == "patient":
        return redirect(url_for("patient_dashboard"))
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        phone = request.form.get("phone", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if not all([name, email, phone, password, confirm]):
            flash("Please fill all fields.", "danger")
            return redirect(url_for("register"))

        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            flash("Enter a valid email.", "danger")
            return redirect(url_for("register"))

        if not strong_password(password):
            flash(
                "Password needs 8+ characters, uppercase, lowercase, number and symbol.",
                "danger"
            )
            return redirect(url_for("register"))

        if password != confirm:
            flash("Passwords do not match.", "danger")
            return redirect(url_for("register"))

        try:
            get_db().execute("""
                INSERT INTO users
                (name,email,phone,password_hash,role,specialization,created_at)
                VALUES(?,?,?,?,?,?,?)
            """, (
                name, email, phone,
                generate_password_hash(password),
                "patient", "",
                datetime.now().isoformat(timespec="seconds")
            ))
            get_db().commit()

        except sqlite3.IntegrityError:
            flash("Email already registered.", "danger")
            return redirect(url_for("register"))

        flash("Registration successful. Please login.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if email == ADMIN_EMAIL and password == ADMIN_PASSWORD:
            session.clear()
            session.update(
                user_id=0,
                name="Administrator",
                email=ADMIN_EMAIL,
                role="admin"
            )
            return redirect(url_for("admin_dashboard"))

        user = get_db().execute(
            "SELECT * FROM users WHERE email=?",
            (email,)
        ).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session.update(
                user_id=user["id"],
                name=user["name"],
                email=user["email"],
                role=user["role"]
            )
            return redirect(url_for("dashboard"))

        flash("Invalid email or password.", "danger")

    return render_template("login.html")


@app.route("/dashboard")
@login_required()
def dashboard():
    routes = {
        "admin": "admin_dashboard",
        "doctor": "doctor_dashboard",
        "patient": "patient_dashboard"
    }
    endpoint = routes.get(session.get("role"))
    if not endpoint:
        session.clear()
        return redirect(url_for("login"))
    return redirect(url_for(endpoint))


@app.route("/patient/dashboard")
@login_required("patient")
def patient_dashboard():
    db = get_db()
    uid = session["user_id"]

    patient = db.execute(
        "SELECT * FROM users WHERE id=? AND role='patient'",
        (uid,)
    ).fetchone()

    assigned = db.execute("""
        SELECT d.name,d.email,d.specialization
        FROM patient_doctor pd
        JOIN users d ON d.id=pd.doctor_id
        WHERE pd.patient_id=?
    """, (uid,)).fetchone()

    doctors = db.execute("""
        SELECT id,name,specialization
        FROM users WHERE role='doctor'
        ORDER BY name
    """).fetchall()

    appointments = db.execute("""
        SELECT a.*,d.name AS doctor_name,d.specialization
        FROM appointments a
        JOIN users d ON d.id=a.doctor_id
        WHERE a.patient_id=?
        ORDER BY a.appointment_date DESC
    """, (uid,)).fetchall()

    medical_files = db.execute("""
        SELECT * FROM medical_files
        WHERE patient_id=?
        ORDER BY uploaded_at DESC
    """, (uid,)).fetchall()

    return render_template(
        "patient_dashboard.html",
        patient=patient,
        assigned_doctor=assigned,
        doctors=doctors,
        appointments=appointments,
        medical_files=medical_files,
        today=datetime.now().date().isoformat()
    )


@app.route("/patient/appointment", methods=["POST"])
@login_required("patient")
def book_appointment():
    doctor_id = request.form.get("doctor_id", type=int)
    date = request.form.get("appointment_date", "")
    reason = request.form.get("reason", "").strip()

    try:
        datetime.strptime(date, "%Y-%m-%d")
    except ValueError:
        flash("Choose a valid appointment date.", "danger")
        return redirect(url_for("patient_dashboard"))

    if date < datetime.now().date().isoformat() or not reason or len(reason) > 500:
        flash("Choose a future date and enter a reason (up to 500 characters).", "danger")
        return redirect(url_for("patient_dashboard"))

    doctor = get_db().execute(
        "SELECT id FROM users WHERE id=? AND role='doctor'",
        (doctor_id,)
    ).fetchone()

    if not doctor:
        flash("Choose a valid doctor.", "danger")
        return redirect(url_for("patient_dashboard"))

    get_db().execute("""
        INSERT INTO appointments
        (patient_id,doctor_id,appointment_date,reason,status,created_at)
        VALUES(?,?,?,?,?,?)
    """, (
        session["user_id"], doctor_id, date, reason,
        "Pending", datetime.now().isoformat(timespec="seconds")
    ))
    get_db().commit()

    flash("Appointment request submitted.", "success")
    return redirect(url_for("patient_dashboard"))


@app.route("/doctor/dashboard")
@login_required("doctor")
def doctor_dashboard():
    db = get_db()
    uid = session["user_id"]

    patients = db.execute("""
        SELECT p.id,p.name,p.email,p.phone
        FROM patient_doctor pd
        JOIN users p ON p.id=pd.patient_id
        WHERE pd.doctor_id=?
        ORDER BY p.name
    """, (uid,)).fetchall()

    appointments = db.execute("""
        SELECT a.*,p.name AS patient_name,p.email AS patient_email
        FROM appointments a
        JOIN users p ON p.id=a.patient_id
        WHERE a.doctor_id=?
        ORDER BY a.appointment_date DESC
    """, (uid,)).fetchall()

    return render_template(
        "doctor_dashboard.html",
        assigned_patients=patients,
        appointments=appointments
    )


@app.route("/doctor/appointment/<int:aid>", methods=["POST"])
@login_required("doctor")
def update_appointment(aid):
    status = request.form.get("status", "")

    if status not in ("Pending", "Approved", "Completed", "Cancelled"):
        flash("Invalid status.", "danger")
        return redirect(url_for("doctor_dashboard"))

    cur = get_db().execute("""
        UPDATE appointments SET status=?
        WHERE id=? AND doctor_id=?
    """, (status, aid, session["user_id"]))

    get_db().commit()

    if cur.rowcount:
        flash("Appointment updated.", "success")
    else:
        flash("Appointment not found.", "danger")

    return redirect(url_for("doctor_dashboard"))


@app.route("/admin/dashboard")
@login_required("admin")
def admin_dashboard():
    db = get_db()

    patients = db.execute("""
        SELECT p.id,p.name,p.email,p.phone,
               pd.doctor_id AS assigned_doctor_id,
               d.name AS assigned_doctor_name,
               d.specialization AS assigned_specialization
        FROM users p
        LEFT JOIN patient_doctor pd ON pd.patient_id=p.id
        LEFT JOIN users d ON d.id=pd.doctor_id
        WHERE p.role='patient'
        ORDER BY p.id DESC
    """).fetchall()

    doctors = db.execute("""
        SELECT * FROM users
        WHERE role='doctor'
        ORDER BY name
    """).fetchall()

    appointments = db.execute("""
        SELECT a.*,p.name AS patient_name,d.name AS doctor_name
        FROM appointments a
        JOIN users p ON p.id=a.patient_id
        JOIN users d ON d.id=a.doctor_id
        ORDER BY a.id DESC
    """).fetchall()

    medical_files = db.execute("""
        SELECT m.*,p.name AS patient_name
        FROM medical_files m
        JOIN users p ON p.id=m.patient_id
        ORDER BY m.uploaded_at DESC
    """).fetchall()

    return render_template(
        "admin_dashboard.html",
        patients=patients,
        doctors=doctors,
        appointments=appointments,
        medical_files=medical_files
    )


@app.route("/admin/assign-doctor", methods=["POST"])
@login_required("admin")
def assign_doctor():
    pid = request.form.get("patient_id", type=int)
    did = request.form.get("doctor_id", type=int)
    db = get_db()

    patient = db.execute(
        "SELECT id FROM users WHERE id=? AND role='patient'", (pid,)
    ).fetchone()
    doctor = db.execute(
        "SELECT id FROM users WHERE id=? AND role='doctor'", (did,)
    ).fetchone()

    if not patient or not doctor:
        flash("Select a valid patient and doctor.", "danger")
        return redirect(url_for("admin_dashboard"))

    db.execute("""
        INSERT INTO patient_doctor(patient_id,doctor_id,assigned_at)
        VALUES(?,?,?)
        ON CONFLICT(patient_id)
        DO UPDATE SET doctor_id=excluded.doctor_id,
                      assigned_at=excluded.assigned_at
    """, (pid, did, datetime.now().isoformat(timespec="seconds")))

    db.commit()
    flash("Doctor assigned successfully.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/upload-medical-file", methods=["POST"])
@app.route("/doctor/upload-medical-file", methods=["POST"])
@login_required()
def upload_medical_file():
    patient_id = request.form.get("patient_id", type=int)
    title = request.form.get("title", "").strip()
    uploaded = request.files.get("file")

    if not patient_id or not title or not uploaded or not uploaded.filename:
        flash("Patient, title and file are required.", "danger")
        return redirect(url_for("admin_dashboard"))

    original = secure_filename(uploaded.filename)
    if not original or "." not in original:
        flash("Invalid file name.", "danger")
        return redirect(url_for("admin_dashboard"))

    ext = original.rsplit(".", 1)[-1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        flash("Allowed formats: PDF, PNG, JPG, JPEG.", "danger")
        return redirect(url_for("admin_dashboard"))

    patient = get_db().execute(
        "SELECT id FROM users WHERE id=? AND role='patient'",
        (patient_id,)
    ).fetchone()

    if not patient:
        flash("Choose a valid patient.", "danger")
        return redirect(url_for("admin_dashboard"))

    stored = f"{datetime.now().strftime('%Y%m%d%H%M%S%f')}_{original}"
    uploaded.save(os.path.join(UPLOAD_DIR, stored))

    lower_title = title.lower()
    kind = (
        "X-Ray"
        if any(term in lower_title for term in ("xray", "x-ray", "x ray"))
        else "Medical Report"
    )

    db = get_db()
    db.execute("""
        INSERT INTO medical_files
        (patient_id,uploaded_by,title,file_name,file_type,uploaded_at)
        VALUES(?,?,?,?,?,?)
    """, (
        patient_id, session["user_id"], title, stored, kind,
        datetime.now().isoformat(timespec="seconds")
    ))
    db.commit()

    flash(f"{kind} uploaded for patient successfully.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/medical-file/<int:file_id>")
@login_required()
def view_medical_file(file_id):
    db = get_db()
    row = db.execute(
        "SELECT * FROM medical_files WHERE id=?",
        (file_id,)
    ).fetchone()

    if not row:
        abort(404)

    role = session.get("role")
    uid = session.get("user_id")

    allowed = role == "admin"

    if role == "patient" and row["patient_id"] == uid:
        allowed = True

    if role == "doctor":
        assigned = db.execute("""
            SELECT 1 FROM patient_doctor
            WHERE patient_id=? AND doctor_id=?
        """, (row["patient_id"], uid)).fetchone()
        allowed = bool(assigned)

    if not allowed:
        abort(403)

    extension = row["file_name"].rsplit(".", 1)[-1]
    download_name = secure_filename(row["title"]) + "." + extension

    return send_from_directory(
        UPLOAD_DIR,
        row["file_name"],
        as_attachment=False,
        download_name=download_name
    )


@app.route("/admin/add-doctor", methods=["POST"])
@login_required("admin")
def add_doctor():
    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip().lower()
    phone = request.form.get("phone", "").strip()
    specialization = request.form.get("specialization", "").strip()
    password = request.form.get("password", "")

    if not all([name, email, phone, specialization, password]):
        flash("Complete all doctor fields.", "danger")
        return redirect(url_for("admin_dashboard"))

    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        flash("Enter a valid email.", "danger")
        return redirect(url_for("admin_dashboard"))

    if not strong_password(password):
        flash("Password must include uppercase, lowercase, number and symbol (8+ characters).", "danger")
        return redirect(url_for("admin_dashboard"))

    try:
        get_db().execute("""
            INSERT INTO users
            (name,email,phone,password_hash,role,specialization,created_at)
            VALUES(?,?,?,?,?,?,?)
        """, (
            name, email, phone, generate_password_hash(password),
            "doctor", specialization,
            datetime.now().isoformat(timespec="seconds")
        ))
        get_db().commit()
        flash("Doctor account created.", "success")

    except sqlite3.IntegrityError:
        flash("That email is already registered.", "danger")

    return redirect(url_for("admin_dashboard"))


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("index"))


@app.errorhandler(413)
def file_too_large(error):
    return "File too large. Maximum allowed size is 10 MB.", 413


init_db()

if __name__ == "__main__":
    app.run(debug=True)

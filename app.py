import os
import re
import hashlib
import sqlite3
import json
import tempfile

from reportlab.lib import colors
from reportlab.lib.colors import HexColor
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.utils import simpleSplit

from datetime import datetime, timezone
from pathlib import Path

from flask import (
    Flask, render_template, request,
    redirect, url_for, flash, send_file
)

from werkzeug.utils import secure_filename
from pypdf import PdfReader

from incident_summary import generate_incident_summary


ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "instance"
EVIDENCE_DIR = DATA_DIR / "evidence"
DB_PATH = DATA_DIR / "tracekit.db"

ALLOWED_EXTENSIONS = {
    "txt", "log", "csv", "png", "jpg", "jpeg", "pdf"
}

MAX_CONTENT_LENGTH = 10 * 1024 * 1024

DATA_DIR.mkdir(exist_ok=True)
EVIDENCE_DIR.mkdir(exist_ok=True)

app = Flask(__name__)

app.secret_key = os.environ.get(
    "TRACEKIT_SECRET_KEY",
    "dev-only-change-this"
)

app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH


# ---------------- DATABASE ----------------

def connect_db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


def init_db():
    with connect_db() as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                original_name TEXT NOT NULL,
                stored_name TEXT NOT NULL,
                uploaded_by TEXT NOT NULL,
                uploaded_at TEXT NOT NULL,
                sha256 TEXT NOT NULL
            )
        """)


# ---------------- FILE HASHING ----------------

def sha256_file(path):
    digest = hashlib.sha256()

    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            digest.update(chunk)

    return digest.hexdigest()


def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


def get_evidence(evidence_id):
    with connect_db() as con:
        return con.execute(
            "SELECT * FROM evidence WHERE id=?",
            (evidence_id,)
        ).fetchone()


# ---------------- EVENT PARSER ----------------

def parse_events(path):
    """Parse log events with multiple timestamp formats."""

    events = []

    pattern = re.compile(
        r"^(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}"
        r"(?:[.,]\d{1,6})?)\s+(.*)$"
    )

    def classify_event(message):
        upper = message.upper()

        if any(word in upper for word in [
            "FAILED_LOGIN",
            "LOGIN FAILED",
            "AUTH FAILURE",
            "AUTHENTICATION FAILED",
            "INVALID PASSWORD",
            "LOGIN FAILURE"
        ]):
            category = "Failed login"

        elif any(word in upper for word in [
            "SUCCESS_LOGIN",
            "LOGIN SUCCESS",
            "AUTH SUCCESS",
            "USER LOGGED IN",
            "LOGIN ACCEPTED"
        ]):
            category = "Successful login"

        elif any(word in upper for word in [
            "CREATE ADMIN",
            "NEW ADMIN",
            "ADMIN CREATED",
            "ADMIN ACCOUNT CREATED",
            "NEW ADMIN USER",
            "ADD USER TO ADMIN",
            "USER CREATED ROLE=ADMIN"
        ]):
            category = "Admin activity"

        elif any(word in upper for word in [
            "DELETE",
            "REMOVED",
            "FILE DELETED",
            "FILE REMOVED"
        ]):
            category = "File activity"

        else:
            category = "Other event"

        if category in ["Admin activity", "File activity"]:
            priority = "High"

        elif category in ["Failed login", "Successful login"]:
            priority = "Medium"

        else:
            priority = "Low"

        return category, priority

    try:
        with open(
            path,
            "r",
            encoding="utf-8",
            errors="replace"
        ) as f:

            for line_no, raw in enumerate(f, start=1):
                line = raw.strip()

                if not line:
                    continue

                match = pattern.match(line)

                if match:
                    timestamp, message = match.groups()

                    normalized = (
                        timestamp.replace("T", " ").replace(",", ".")
                    )

                    try:
                        if "." in normalized:
                            dt = datetime.strptime(
                                normalized,
                                "%Y-%m-%d %H:%M:%S.%f"
                            )
                        else:
                            dt = datetime.strptime(
                                normalized,
                                "%Y-%m-%d %H:%M:%S"
                            )

                    except ValueError:
                        continue

                    category, priority = classify_event(message)

                    events.append({
                        "timestamp": dt,
                        "display_time": dt.strftime(
                            "%Y-%m-%d %H:%M:%S"
                        ),
                        "message": message,
                        "category": category,
                        "priority": priority,
                        "line": line_no
                    })

                elif events:
                    events[-1]["message"] += "\n" + line

                    category, priority = classify_event(
                        events[-1]["message"]
                    )

                    events[-1]["category"] = category
                    events[-1]["priority"] = priority

    except (OSError, UnicodeError):
        return []

    return sorted(
        events,
        key=lambda item: item["timestamp"]
    )


# ---------------- PDF TEXT EXTRACTION ----------------

def parse_pdf_events(path):
    """Extract selectable PDF text and parse timestamped events."""

    temp_path = None

    try:
        reader = PdfReader(str(path))

        if reader.is_encrypted:
            return []

        extracted_text = "\n".join(
            page.extract_text() or ""
            for page in reader.pages
        )

        if not extracted_text.strip():
            return []

        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            suffix=".txt",
            delete=False
        ) as temp_file:

            temp_file.write(extracted_text)
            temp_path = temp_file.name

        return parse_events(temp_path)

    except Exception as e:
        print(f"PDF extraction error: {e}")
        return []

    finally:
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)

    # ---------------- RED FLAG DETECTION ----------------

def detect_flags(events):

    flags = []

    # Rule 1: Repeated failed login attempts
    failed = [
        e for e in events
        if e["category"] == "Failed login"
    ]

    if len(failed) >= 5:
        flags.append(
            f"RED FLAG: {len(failed)} failed login attempts detected. "
            "Possible repeated login attack."
        )

    # Rule 2: Successful login after failed attempts
    for i, event in enumerate(events):

        if event["category"] == "Successful login":

            previous_fails = sum(
                1 for e in events[max(0, i - 10):i]
                if e["category"] == "Failed login"
            )

            if previous_fails >= 3:
                flags.append(
                    f"RED FLAG: Successful login detected after "
                    f"{previous_fails} failed login attempts."
                )
                break

    # Rule 3: New admin account creation
    for event in events:

        message = event["message"].upper()

        admin_keywords = [
            "CREATE ADMIN",
            "ADMIN ACCOUNT CREATED",
            "NEW ADMIN USER",
            "ADD USER TO ADMIN",
            "USER CREATED ROLE=ADMIN"
        ]

        if any(keyword in message for keyword in admin_keywords):

            flags.append(
                f"RED FLAG: Possible admin account creation "
                f"at {event['display_time']}: {event['message']}"
            )

    # Rule 4: File deletion or removal
    for event in events:

        if event["category"] == "File activity":

            message = event["message"].upper()

            if "DELETE" in message or "REMOVED" in message:

                flags.append(
                    f"RED FLAG: File deletion/removal activity "
                    f"at {event['display_time']}: {event['message']}"
                )

    return flags


# ---------------- HOME PAGE ----------------

@app.route("/")
def index():

    with connect_db() as con:
        records = con.execute(
            "SELECT * FROM evidence ORDER BY id DESC"
        ).fetchall()

    return render_template(
        "index.html",
        records=records
    )


# ---------------- EVIDENCE UPLOAD ----------------

@app.route("/upload", methods=["POST"])
def upload():

    files = request.files.getlist("evidence_files")

    uploader = (
        request.form.get("uploader")
        or "Demo Investigator"
    ).strip()[:100]

    # Remove empty file selections
    files = [
        file for file in files
        if file and file.filename
    ]

    if not files:
        flash("Please choose at least one file.", "error")
        return redirect(url_for("index"))

    uploaded_count = 0
    failed_files = []

    for file in files:

        # Validate file type
        if not allowed_file(file.filename):
            failed_files.append(file.filename)
            continue

        original_name = secure_filename(
            file.filename
        ) or "uploaded_file"

        # Generate a unique filename
        stamp = datetime.now(timezone.utc).strftime(
            "%Y%m%dT%H%M%S%fZ"
        )

        stored_name = f"{stamp}_{original_name}"
        target = EVIDENCE_DIR / stored_name

        try:
            # Save evidence
            file.save(target)

            # Generate SHA-256 fingerprint
            digest = sha256_file(target)

            uploaded_at = datetime.now(
                timezone.utc
            ).isoformat(timespec="seconds")

            # Store evidence metadata
            with connect_db() as con:

                con.execute(
                    """
                    INSERT INTO evidence
                    (original_name, stored_name, uploaded_by, uploaded_at, sha256)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        original_name,
                        stored_name,
                        uploader,
                        uploaded_at,
                        digest
                    )
                )

            uploaded_count += 1

        except Exception as e:
            print(f"Upload error: {e}")

            # Remove incomplete file
            if target.exists():
                target.unlink()

            failed_files.append(original_name)

    # Show upload result
    if uploaded_count > 0:
        flash(
            f"{uploaded_count} evidence file(s) uploaded and sealed successfully.",
            "success"
        )

    if failed_files:
        flash(
            "These files could not be uploaded: "
            + ", ".join(failed_files),
            "error"
        )

    return redirect(url_for("index"))


# ---------------- CASE DETAILS ----------------

@app.route("/case/<int:evidence_id>")
def case_detail(evidence_id):

    record = get_evidence(evidence_id)

    if not record:
        flash("Evidence record not found.", "error")
        return redirect(url_for("index"))

    path = EVIDENCE_DIR / record["stored_name"]

    ext = (
        record["original_name"].rsplit(".", 1)[-1].lower()
        if "." in record["original_name"]
        else ""
    )

    # Parse supported evidence formats
    if ext in {"txt", "log", "csv"}:
        events = parse_events(path)

    elif ext == "pdf":
        events = parse_pdf_events(path)

    else:
        events = []

    flags = detect_flags(events)

    story = " ".join(flags[:2]) if flags else (
        "No configured red-flag rules matched the parsed events. "
        "This does not prove that the case is safe."
        if events else
        "No timeline events were parsed. For this demo, use a TXT "
        "or LOG file with timestamps in YYYY-MM-DD HH:MM:SS format."
    )

    return render_template(
        "case.html",
        record=record,
        events=events,
        flags=flags,
        story=story
    )


# ---------------- HASH VERIFICATION ----------------

@app.route("/verify/<int:evidence_id>", methods=["GET", "POST"])
def verify(evidence_id):

    record = get_evidence(evidence_id)

    if not record:
        flash("Evidence record not found.", "error")
        return redirect(url_for("index"))

    verdict = None

    if request.method == "POST":

        candidate = request.files.get("candidate_file")

        if not candidate or not candidate.filename:
            flash(
                "Choose the file you want to verify.",
                "error"
            )

        else:

            temp_path = DATA_DIR / (
                f"verify_{datetime.now().timestamp()}.tmp"
            )

            try:
                candidate.save(temp_path)

                candidate_hash = sha256_file(temp_path)

                verdict = (
                    "MATCH — same SHA-256 fingerprint"
                    if candidate_hash == record["sha256"]
                    else
                    "MISMATCH — file differs from the recorded fingerprint"
                )

            finally:
                temp_path.unlink(missing_ok=True)

    return render_template(
        "verify.html",
        record=record,
        verdict=verdict
    ) 

    # ---------------- INCIDENT PDF REPORT ----------------

@app.route("/report/<int:evidence_id>")
def generate_report(evidence_id):

    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas
    from reportlab.lib.utils import simpleSplit

    evidence = get_evidence(evidence_id)

    if not evidence:
        flash("Evidence not found.")
        return redirect(url_for("index"))

    path = EVIDENCE_DIR / evidence["stored_name"]

    ext = evidence["original_name"].rsplit(".", 1)[-1].lower()

    if ext in {"txt", "log", "csv"}:
        events = parse_events(path)

    elif ext == "pdf":
        events = parse_pdf_events(path)

    else:
        events = []

    flags = detect_flags(events)

    out_path = DATA_DIR / f"TraceKit_Report_{evidence_id}.pdf"

    pdf = canvas.Canvas(str(out_path), pagesize=A4)

    width, height = A4
    y = height - 50

    def write_line(text, font="Helvetica", size=10):
        nonlocal y

        pdf.setFont(font, size)

        lines = simpleSplit(str(text), font, size, width - 100)

        for line in lines:
            if y < 50:
                pdf.showPage()
                y = height - 50
                pdf.setFont(font, size)

            pdf.drawString(50, y, line)
            y -= 16

    pdf.setTitle("TraceKit Incident Report")

    write_line("TRACEKIT - INCIDENT REPORT", "Helvetica-Bold", 18)
    y -= 15

    write_line(f"Evidence ID: {evidence['id']}")
    write_line(f"Original File: {evidence['original_name']}")
    write_line(f"Uploaded By: {evidence['uploaded_by']}")
    write_line(f"Uploaded At: {evidence['uploaded_at']}")
    write_line(f"SHA-256: {evidence['sha256']}")

    y -= 20

    write_line("DETECTED RED FLAGS", "Helvetica-Bold", 14)
    y -= 5

    if flags:
        for flag in flags:
            write_line(f"- {flag}")
    else:
        write_line("No red flags detected.")

    y -= 20

    write_line("INCIDENT TIMELINE", "Helvetica-Bold", 14)
    y -= 5

    if events:
        for event in events:
            write_line(
                f"{event.get('timestamp', 'Unknown time')} | "
                f"{event.get('category', 'Event')} | "
                f"{event.get('message', '')}"
            )
    else:
        write_line("No timeline events available.")

    pdf.save()

    return send_file(
        out_path,
        as_attachment=True,
        download_name=out_path.name
    )


# ---------------- HDFS ANOMALY DASHBOARD ----------------

@app.route("/hdfs")
def hdfs_dashboard():

    report_path = ROOT / "hdfs_anomaly_report.json"

    anomalies = []

    if report_path.exists():
        with open(report_path, "r", encoding="utf-8") as file:
            anomalies = json.load(file)

    severity_counts = {
        "LOW": 0,
        "MEDIUM": 0,
        "HIGH": 0
    }

    for anomaly in anomalies:
        severity = str(anomaly.get("severity", "LOW")).upper()

        if severity in severity_counts:
            severity_counts[severity] += 1

    incident_summary = generate_incident_summary()

    return render_template(
        "hdfs.html",
        total_anomalies=len(anomalies),
        severity_counts=severity_counts,
        anomalies=anomalies,
        incident_summary=incident_summary
    )


# ---------------- FILE SIZE ERROR ----------------

@app.errorhandler(413)
def file_too_large(error):

    flash("File is too large. Maximum allowed size is 10 MB.")

    return redirect(url_for("index"))


# ---------------- RUN APPLICATION ----------------

# Initialize database when the app starts.
# This also works when the app runs through Gunicorn on Render.

init_db()

if __name__ == "__main__":
    app.run(debug=True)      
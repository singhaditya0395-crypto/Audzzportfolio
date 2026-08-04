import json
import os
import smtplib
from datetime import datetime, timezone
from email.mime.text import MIMEText
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr

# This is the Vercel-deployed copy of the backend. Vercel's Root Directory for
# this project is set to Frontend/Public, so only files under here are visible
# to the build — that's why this can't just import ../../Backend/main.py.
# Keep this in sync with Backend/main.py (used for local dev) when editing.

GMAIL_ADDRESS = os.getenv("GMAIL_ADDRESS")
GMAIL_APP_PASSWORD = os.getenv("GMAIL_APP_PASSWORD")
NOTIFY_EMAIL = os.getenv("NOTIFY_EMAIL", "singh.aditya0395@gmail.com")

# Vercel Functions only have a writable filesystem at /tmp, and it's not
# persistent across cold starts/instances — this log is best-effort only.
# The Gmail notification is the durable record.
DEFAULT_LOG_PATH = "/tmp/meetings_log.jsonl" if os.getenv("VERCEL") else str(Path(__file__).parent / "data" / "meetings_log.jsonl")
LOG_FILE_PATH = Path(os.getenv("LOG_FILE_PATH", DEFAULT_LOG_PATH))

FRONTEND_ORIGINS = [
    origin.strip()
    for origin in os.getenv("FRONTEND_ORIGINS", "*").split(",")
    if origin.strip()
]

app = FastAPI(title="Aditya Singh Portfolio API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=FRONTEND_ORIGINS,
    allow_credentials=False,
    allow_methods=["POST", "GET"],
    allow_headers=["Content-Type"],
)


class MeetingRequest(BaseModel):
    topic: str
    name: str
    email: EmailStr
    organization: str
    role: str
    notes: str


def log_meeting_to_file(data: MeetingRequest) -> None:
    record = {"received_at": datetime.now(timezone.utc).isoformat(), **data.model_dump()}
    LOG_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(LOG_FILE_PATH, "a") as log_file:
        log_file.write(json.dumps(record) + "\n")


def send_meeting_email(data: MeetingRequest) -> None:
    if not GMAIL_ADDRESS or not GMAIL_APP_PASSWORD:
        print("[Email] Skipped: GMAIL_ADDRESS / GMAIL_APP_PASSWORD not set in Vercel env vars")
        return

    body = (
        f"New virtual coffee request via portfolio site\n\n"
        f"Topic: {data.topic}\n"
        f"Name: {data.name}\n"
        f"Email: {data.email}\n"
        f"Organization: {data.organization}\n"
        f"Role: {data.role}\n\n"
        f"Notes:\n{data.notes}\n"
    )
    message = MIMEText(body)
    message["Subject"] = f"[Portfolio] New meeting request: {data.topic}"
    message["From"] = GMAIL_ADDRESS
    message["To"] = NOTIFY_EMAIL
    message["Reply-To"] = data.email

    with smtplib.SMTP("smtp.gmail.com", 587) as server:
        server.starttls()
        server.login(GMAIL_ADDRESS, GMAIL_APP_PASSWORD)
        server.sendmail(GMAIL_ADDRESS, [NOTIFY_EMAIL], message.as_string())


@app.get("/api/health")
def health_check():
    return {"status": "healthy", "service": "python-backend-engine"}


@app.post("/api/meetings")
def create_meeting(data: MeetingRequest):
    print(f"[API] Meeting questionnaire received from {data.name} ({data.organization}) for topic: {data.topic}")

    try:
        log_meeting_to_file(data)
    except Exception as exc:
        print(f"[Log] Failed to write local backup log: {exc}")

    try:
        send_meeting_email(data)
    except Exception as exc:
        # Don't block the visitor's booking flow on an email misconfiguration;
        # just surface it loudly server-side so it gets fixed.
        print(f"[Email] Failed to send notification: {exc}")

    return {
        "success": True,
        "message": "Questionnaire saved successfully. Proceeding to calendar schedule.",
        "submitted_data": data.model_dump(),
    }

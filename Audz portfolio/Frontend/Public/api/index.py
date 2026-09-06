import hashlib
import hmac
import json
import os
import re
import secrets
import smtplib
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from email.mime.text import MIMEText
from pathlib import Path
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field, field_validator

# This is the Vercel-deployed copy of the backend. Vercel's Root Directory for
# this project is set to Frontend/Public, so only files under here are visible
# to the build — that's why this can't just import ../../Backend/main.py.
# Keep this in sync with Backend/main.py (used for local dev) when editing.

GMAIL_ADDRESS = os.getenv("GMAIL_ADDRESS")
GMAIL_APP_PASSWORD = os.getenv("GMAIL_APP_PASSWORD")
NOTIFY_EMAIL = os.getenv("NOTIFY_EMAIL")

# Vercel Functions only have a writable filesystem at /tmp, and it's not
# persistent across cold starts/instances — this log is best-effort only.
# The Gmail notification is the durable record. It is NOT a substitute for the
# encrypted, TTL'd Upstash record below, which is what the data-rights
# endpoints (view/delete) actually read from.
DEFAULT_LOG_PATH = "/tmp/meetings_log.jsonl" if os.getenv("VERCEL") else str(Path(__file__).parent / "data" / "meetings_log.jsonl")
LOG_FILE_PATH = Path(os.getenv("LOG_FILE_PATH", DEFAULT_LOG_PATH))

# Same-origin in production (the frontend and this function are deployed together),
# so this only ever needs to reject OTHER sites' scripts from calling the API —
# not restrict the site's own requests. Defaults to the real production domain
# instead of "*". Override with a comma-separated list via FRONTEND_ORIGINS if you
# need a preview URL or custom domain allowed too.
FRONTEND_ORIGINS = [
    origin.strip()
    for origin in os.getenv("FRONTEND_ORIGINS", "https://audzzportfolio.vercel.app").split(",")
    if origin.strip()
]

# Upstash Redis (REST API, works fine from a stateless serverless function — no
# persistent connection needed). Used for two independent, optional features:
#   1. Rate limiting (50 req/hour/IP)
#   2. Encrypted submission storage backing the data-rights endpoints below,
#      with a native TTL enforcing the 30-day retention period.
# If these aren't set, both features fail open / stay inactive rather than
# breaking the core "email me a meeting request" flow.
UPSTASH_REDIS_REST_URL = os.getenv("UPSTASH_REDIS_REST_URL")
UPSTASH_REDIS_REST_TOKEN = os.getenv("UPSTASH_REDIS_REST_TOKEN")
RATE_LIMIT_PER_HOUR = 50
RETENTION_SECONDS = 30 * 24 * 60 * 60  # 30 days
AUDIT_RETENTION_SECONDS = 90 * 24 * 60 * 60  # keep audit trail longer than the data itself

# Symmetric encryption for the email address in the stored submission record.
# Generate a key with: python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
DATA_ENCRYPTION_KEY = os.getenv("DATA_ENCRYPTION_KEY")
_fernet: Optional[Fernet] = None
if DATA_ENCRYPTION_KEY:
    try:
        _fernet = Fernet(DATA_ENCRYPTION_KEY.encode())
    except Exception as exc:
        print(f"[Encryption] DATA_ENCRYPTION_KEY is invalid, persistent submission storage disabled: {exc}")

# The submissions store (and therefore /api/submissions/*) only activates when
# BOTH Redis and a valid encryption key are configured. Storing PII persistently
# without encryption would be worse than not storing it at all, so this never
# silently falls back to writing plaintext.
SUBMISSIONS_ENABLED = bool(UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN and _fernet)

# Cloudflare Turnstile (invisible/managed CAPTCHA, no third-party tracking).
# SITE_KEY is public by design - Turnstile's own widget script needs it
# client-side, so it's handed out via /api/contact rather than hidden. Only
# SECRET_KEY (used server-side to verify a solved challenge) is sensitive.
# Complements, doesn't replace, the existing honeypot. If unset, verification
# fails open (submissions are accepted without it) - same pattern as the rest
# of this file's optional features.
TURNSTILE_SITE_KEY = os.getenv("TURNSTILE_SITE_KEY")
TURNSTILE_SECRET_KEY = os.getenv("TURNSTILE_SECRET_KEY")

app = FastAPI(title="Aditya Singh Portfolio API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=FRONTEND_ORIGINS,
    allow_credentials=False,
    allow_methods=["POST", "GET", "DELETE"],
    allow_headers=["Content-Type"],
)


_CONTROL_CHARS = re.compile(r"[\r\n\x00-\x08\x0b\x0c\x0e-\x1f]")
# Defense-in-depth against stored XSS: nothing in this codebase currently
# renders user input as HTML (checked - only textContent/plaintext-email/JSON
# ever touch these values), so this isn't closing a live hole today. It's here
# so a future feature that DOES render this data as HTML doesn't reopen one.
_DANGEROUS_PATTERN = re.compile(
    r"<\s*script|<\s*iframe|javascript:|data:text/html|on\w+\s*=", re.IGNORECASE
)


class MeetingRequest(BaseModel):
    topic: str = Field(..., min_length=1, max_length=120)
    name: str = Field(..., min_length=1, max_length=100)
    email: EmailStr
    organization: str = Field(..., min_length=1, max_length=150)
    role: str = Field(..., min_length=1, max_length=100)
    notes: str = Field(..., min_length=1, max_length=2000)
    consent: bool = Field(...)
    # IANA zone name (e.g. "America/New_York"), detected client-side via the
    # native Intl API. Optional and informational only - included in the email
    # so the host has cross-timezone context when picking an actual time.
    timezone: str = Field("", max_length=100)
    # Honeypot: a field real visitors never see or fill in (hidden off-screen on the
    # frontend, not display:none — bots specifically check for and skip that).
    # Bots that auto-fill every form field trip it; humans never do.
    website: str = Field("", max_length=200)
    # Cloudflare Turnstile's solved-challenge token, verified server-side below.
    turnstile_token: str = Field("", max_length=2048)

    @field_validator("topic", "name", "organization", "role", "notes")
    @classmethod
    def strip_and_reject_control_chars(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("This field can't be empty.")
        if _CONTROL_CHARS.search(value):
            raise ValueError("This field contains characters that aren't allowed.")
        if _DANGEROUS_PATTERN.search(value):
            raise ValueError("This field contains content that isn't allowed.")
        return value

    @field_validator("name")
    @classmethod
    def name_characters_only(cls, value: str) -> str:
        # str.isalpha() is Unicode-aware, so "José" and "Nguyễn" pass same as
        # "Sarah". Apostrophe is allowed beyond the literal "spaces, hyphens"
        # spec, since rejecting it would break very common real names (O'Brien).
        if not all(ch.isalpha() or ch in " '-" for ch in value):
            raise ValueError("Name can only contain letters, spaces, and hyphens.")
        return value

    @field_validator("timezone")
    @classmethod
    def sanitize_timezone(cls, value: str) -> str:
        value = value.strip()
        if _CONTROL_CHARS.search(value):
            raise ValueError("Timezone contains characters that aren't allowed.")
        return value

    @field_validator("email")
    @classmethod
    def email_length_limit(cls, value: str) -> str:
        # RFC 5321 caps an address at 254 characters; EmailStr already validates format.
        if len(value) > 254:
            raise ValueError("Email address is too long.")
        return value

    @field_validator("consent")
    @classmethod
    def require_consent(cls, value: bool) -> bool:
        if not value:
            raise ValueError("You must agree to be contacted before submitting.")
        return value


def mask_email(email: str) -> str:
    local, _, domain = email.partition("@")
    if not domain:
        return "***"
    masked_local = local[0] + "***" if local else "***"
    return f"{masked_local}@{domain}"


def mask_name(name: str) -> str:
    first = name.strip().split(" ", 1)[0] if name.strip() else ""
    return f"{first[0]}***" if first else "***"


def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def is_trusted_origin(origin: str) -> bool:
    return any(origin == allowed or origin.startswith(allowed) for allowed in FRONTEND_ORIGINS)


def _redis_pipeline(commands: list) -> Optional[list]:
    """Runs a pipeline of Redis commands via Upstash's REST API. Returns None
    (rather than raising) on any failure, so callers can fail open/inactive."""
    if not (UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN):
        return None
    try:
        body = json.dumps(commands).encode()
        req = urllib.request.Request(
            f"{UPSTASH_REDIS_REST_URL}/pipeline",
            data=body,
            headers={
                "Authorization": f"Bearer {UPSTASH_REDIS_REST_TOKEN}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            return json.loads(resp.read())
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        print(f"[Redis] Request failed: {exc}")
        return None


def check_rate_limit(client_ip: str) -> bool:
    """True if this IP is still under the hourly limit. Fails open (allows the
    request) if Upstash isn't configured or the check itself errors out, so a
    misconfigured/unreachable rate limiter never breaks the form for real visitors."""
    key = f"ratelimit:meetings:{client_ip}"
    result = _redis_pipeline([["INCR", key], ["EXPIRE", key, "3600", "NX"]])
    if result is None:
        return True
    try:
        return result[0]["result"] <= RATE_LIMIT_PER_HOUR
    except (KeyError, IndexError, TypeError):
        return True


def verify_turnstile(token: str, client_ip: str) -> bool:
    """True if the solved challenge is valid. Fails open (allows the request)
    when TURNSTILE_SECRET_KEY isn't configured, matching every other optional
    feature in this file - so the form works before Turnstile is set up, and
    starts actually gating on it the moment a secret key is added."""
    if not TURNSTILE_SECRET_KEY:
        return True
    if not token:
        return False
    try:
        body = urllib.parse.urlencode({
            "secret": TURNSTILE_SECRET_KEY,
            "response": token,
            "remoteip": client_ip,
        }).encode()
        req = urllib.request.Request(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data=body,
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            result = json.loads(resp.read())
        return bool(result.get("success"))
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        print(f"[Turnstile] Verification request failed: {exc}")
        # Network hiccup talking to Cloudflare shouldn't lock out real visitors.
        return True


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def store_submission(data: MeetingRequest) -> Optional[dict]:
    """Writes an encrypted, 30-day-TTL'd copy of the submission to Redis and
    returns the id + a one-time management token, or None if persistent storage
    isn't configured (the core email-notification flow works either way)."""
    if not SUBMISSIONS_ENABLED:
        return None

    submission_id = uuid.uuid4().hex
    token = secrets.token_urlsafe(32)
    record = {
        "id": submission_id,
        "token_hash": hash_token(token),
        "received_at": datetime.now(timezone.utc).isoformat(),
        "topic": data.topic,
        "name": data.name,
        "email": _fernet.encrypt(data.email.encode()).decode(),
        "organization": data.organization,
        "role": data.role,
        "notes": data.notes,
    }
    key = f"submission:{submission_id}"
    result = _redis_pipeline([
        ["SET", key, json.dumps(record)],
        ["EXPIRE", key, str(RETENTION_SECONDS)],
    ])
    if result is None:
        return None
    return {"submission_id": submission_id, "management_token": token}


def get_submission_record(submission_id: str) -> Optional[dict]:
    result = _redis_pipeline([["GET", f"submission:{submission_id}"]])
    if not result:
        return None
    raw = result[0].get("result")
    if not raw:
        return None
    try:
        return json.loads(raw)
    except ValueError:
        return None


def decrypt_email(encrypted_email: str) -> str:
    try:
        return _fernet.decrypt(encrypted_email.encode()).decode()
    except InvalidToken:
        return "[decryption failed]"


def audit_log(action: str, submission_id: str, client_ip: str) -> None:
    """Every access to stored submission data gets recorded here — creation,
    successful reads/deletes, and denied attempts. Printed to Vercel's function
    logs always; also written to Redis (with its own longer retention) when
    available, so the trail survives past a single cold start."""
    entry = {
        "at": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "submission_id": submission_id,
        "ip": client_ip,
    }
    print(f"[Audit] {json.dumps(entry)}")
    audit_key = f"audit:{submission_id}:{int(datetime.now(timezone.utc).timestamp() * 1000)}"
    _redis_pipeline([
        ["SET", audit_key, json.dumps(entry)],
        ["EXPIRE", audit_key, str(AUDIT_RETENTION_SECONDS)],
    ])


def log_meeting_to_file(data: MeetingRequest) -> None:
    record = {"received_at": datetime.now(timezone.utc).isoformat(), **data.model_dump()}
    LOG_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(LOG_FILE_PATH, "a") as log_file:
        log_file.write(json.dumps(record) + "\n")


def send_meeting_email(data: MeetingRequest) -> None:
    if not GMAIL_ADDRESS or not GMAIL_APP_PASSWORD:
        print("[Email] Skipped: GMAIL_ADDRESS / GMAIL_APP_PASSWORD not set in Vercel env vars")
        return
    if not NOTIFY_EMAIL:
        print("[Email] Skipped: NOTIFY_EMAIL not set in Vercel env vars")
        return

    timezone_line = f"Visitor timezone: {data.timezone}\n" if data.timezone else ""
    body = (
        f"New virtual coffee request via portfolio site\n\n"
        f"Topic: {data.topic}\n"
        f"Name: {data.name}\n"
        f"Email: {data.email}\n"
        f"Organization: {data.organization}\n"
        f"Role: {data.role}\n"
        f"{timezone_line}\n"
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


def check_origin(request: Request) -> None:
    origin = request.headers.get("origin") or request.headers.get("referer", "")
    if origin and not is_trusted_origin(origin):
        raise HTTPException(status_code=403, detail="Request origin not allowed.")


@app.get("/api/health")
def health_check():
    return {"status": "healthy", "service": "python-backend-engine"}


@app.get("/api/contact")
def get_contact():
    # Lets the frontend build a "add me as a guest" calendar invite without ever
    # hardcoding the address in the page source. turnstile_site_key is null
    # until TURNSTILE_SITE_KEY is configured - the frontend skips rendering
    # the widget entirely in that case (site keys are meant to be public).
    return {"email": NOTIFY_EMAIL, "turnstile_site_key": TURNSTILE_SITE_KEY}


@app.post("/api/meetings")
def create_meeting(data: MeetingRequest, request: Request):
    # Reject forged cross-site submissions outright (a malicious site's JS can't
    # read the response either way thanks to CORS, but this stops the side effect
    # — the email send / log write — from happening at all, which CORS alone does not).
    check_origin(request)

    client_ip = get_client_ip(request)
    if not check_rate_limit(client_ip):
        raise HTTPException(status_code=429, detail="Too many requests. Please try again in a bit.")

    if not verify_turnstile(data.turnstile_token, client_ip):
        raise HTTPException(status_code=403, detail="Verification failed. Please try again.")

    if data.website:
        # Honeypot tripped: a bot filled in a field real visitors never see.
        # Respond exactly like a real success so the bot doesn't learn to adapt,
        # but skip logging, emailing, and persistent storage entirely.
        print(f"[API] Honeypot tripped, dropping submission from {mask_name(data.name)}")
        return {
            "success": True,
            "message": "Questionnaire saved successfully. Proceeding to calendar schedule.",
            "submitted_data": data.model_dump(),
        }

    print(f"[API] Meeting questionnaire received from {mask_name(data.name)} <{mask_email(data.email)}> "
          f"({data.organization}) for topic: {data.topic}")

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

    storage = store_submission(data)

    response = {
        "success": True,
        "message": "Questionnaire saved successfully. Proceeding to calendar schedule.",
        "submitted_data": data.model_dump(),
    }
    if storage:
        audit_log("create", storage["submission_id"], client_ip)
        # Returned once, here only — this is the visitor's one chance to save it.
        # There's no login system, so this token IS the access control for their
        # own data going forward (see /api/submissions/{id} below).
        response["submission_id"] = storage["submission_id"]
        response["management_token"] = storage["management_token"]
        response["retention_days"] = RETENTION_SECONDS // 86400
    return response


@app.get("/api/submissions/{submission_id}")
def get_my_submission(submission_id: str, token: str, request: Request):
    """'Request my data': returns exactly what was stored for this submission,
    decrypted, if the caller presents the matching management token."""
    check_origin(request)
    client_ip = get_client_ip(request)

    if not SUBMISSIONS_ENABLED:
        raise HTTPException(status_code=503, detail="Data access is not enabled on this deployment.")

    record = get_submission_record(submission_id)
    if not record or not hmac.compare_digest(record.get("token_hash", ""), hash_token(token)):
        audit_log("read_denied", submission_id, client_ip)
        # Same 404 whether the id doesn't exist or the token is wrong - don't
        # reveal which, so a wrong token can't be used to confirm a real id.
        raise HTTPException(status_code=404, detail="Submission not found.")

    audit_log("read", submission_id, client_ip)
    return {
        "id": record["id"],
        "received_at": record["received_at"],
        "topic": record["topic"],
        "name": record["name"],
        "email": decrypt_email(record["email"]),
        "organization": record["organization"],
        "role": record["role"],
        "notes": record["notes"],
    }


@app.delete("/api/submissions/{submission_id}")
def delete_my_submission(submission_id: str, token: str, request: Request):
    """Deletes a stored submission immediately (rather than waiting on the
    30-day TTL) if the caller presents the matching management token."""
    check_origin(request)
    client_ip = get_client_ip(request)

    if not SUBMISSIONS_ENABLED:
        raise HTTPException(status_code=503, detail="Data deletion is not enabled on this deployment.")

    record = get_submission_record(submission_id)
    if not record or not hmac.compare_digest(record.get("token_hash", ""), hash_token(token)):
        audit_log("delete_denied", submission_id, client_ip)
        raise HTTPException(status_code=404, detail="Submission not found.")

    _redis_pipeline([["DEL", f"submission:{submission_id}"]])
    audit_log("delete", submission_id, client_ip)
    return {"success": True, "message": "Your data has been deleted."}

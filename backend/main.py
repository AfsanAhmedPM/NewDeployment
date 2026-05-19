import os
import json
import logging
import uuid
import base64
import collections
from email.mime.text import MIMEText
from typing import List
from pydantic import BaseModel
from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.security import OAuth2PasswordBearer
from dotenv import load_dotenv
from groq import Groq
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from sqlalchemy import create_engine, Column, String, Text
from sqlalchemy.orm import sessionmaker, Session, declarative_base

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- CONFIG ---
GROQ_MODEL = "llama-3.1-8b-instant"
CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
REDIRECT_URI = "https://inboxintelligence-hwb1.onrender.com/auth/callback" # Update if needed
FRONTEND_URL = "https://inbox-intelligence.streamlit.app"

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./test.db")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# --- DATABASE SETUP ---
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    email = Column(String, primary_key=True, index=True)
    credentials_json = Column(Text)
    session_token = Column(String, index=True)

Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

app = FastAPI()
client = Groq(api_key=os.getenv("GROQ_API_KEY"))
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# --- DATA MODELS ---
class GenerateRequest(BaseModel):
    msg_id: str
    intent: str

class SendRequest(BaseModel):
    msg_id: str
    body: str

# --- HELPERS ---
def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.session_token == token).first()
    if not user: raise HTTPException(status_code=401, detail="Invalid Session")
    creds_data = json.loads(user.credentials_json)
    return Credentials.from_authorized_user_info(creds_data)

def create_flow():
    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": [REDIRECT_URI],
            }
        },
        scopes=[
            "openid",
            "https://www.googleapis.com/auth/userinfo.email",
            "https://www.googleapis.com/auth/gmail.modify",
            "https://www.googleapis.com/auth/gmail.compose",
            "https://www.googleapis.com/auth/gmail.send",
        ],
        redirect_uri=REDIRECT_URI,
    )

    # IMPORTANT
    flow.autogenerate_code_verifier = False

    return flow

def create_message(to, subject, body_text):
    message = MIMEText(body_text)
    message['to'] = to
    message['subject'] = subject
    return {'raw': base64.urlsafe_b64encode(message.as_bytes()).decode()}

# --- AI LOGIC ---
def categorize_with_ai(emails):
    empty = {
        "Action Items": [],
        "Applications": [],
        "University": [],
        "Promotions": []
    }

    if not emails:
        return empty

    prompt_lines = [
        f"ID {i} | From: {e['from']} | Sub: {e['subject']} | Body: {e['snippet'][:60]}"
        for i, e in enumerate(emails, 1)
    ]

    system_prompt = """
    Sort emails into exactly these 4 groups:
    1. Action Items
    2. Applications
    3. University
    4. Promotions

    Return ONLY JSON like:
    {
      "Action Items": [1, 3],
      "Applications": [2],
      "University": [],
      "Promotions": [4]
    }
    """

    try:
        completion = client.chat.completions.create(
            model=GROQ_MODEL,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": "\n".join(prompt_lines)}
            ],
            temperature=0.0,
            response_format={"type": "json_object"}
        )

        print("GROQ RAW:", completion.choices[0].message.content)

        category_map = json.loads(completion.choices[0].message.content)
        final_output = {k: [] for k in empty.keys()}

        for cat, ids in category_map.items():
            if cat not in final_output:
                continue
            for eid in ids:
                idx = int(eid) - 1
                if 0 <= idx < len(emails):
                    final_output[cat].append(emails[idx])

        return final_output

    except Exception as e:
        print("GROQ ERROR:", str(e))
        return empty

# --- ROUTES ---
@app.get("/")
def home(): return {"status": "Secretary Mode Online"}

@app.get("/auth/login")
def login():
    flow = create_flow()

    authorization_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent",
    )

    return RedirectResponse(authorization_url)

@app.get("/auth/callback")
def callback(request: Request, db: Session = Depends(get_db)):
    try:
        code = request.query_params.get("code")

        if not code:
            return JSONResponse(
                {"error": "Missing authorization code"},
                status_code=400,
            )

        flow = create_flow()

        flow.fetch_token(
            code=code,
            client_secret=CLIENT_SECRET
        )

        creds = flow.credentials

        service = build("gmail", "v1", credentials=creds)

        profile = service.users().getProfile(userId="me").execute()

        email = profile["emailAddress"]

        new_token = str(uuid.uuid4())

        user = db.query(User).filter(User.email == email).first()

        if not user:
            user = User(
                email=email,
                credentials_json=creds.to_json(),
                session_token=new_token,
            )
            db.add(user)
        else:
            user.credentials_json = creds.to_json()
            user.session_token = new_token

        db.commit()

        return RedirectResponse(f"{FRONTEND_URL}?token={new_token}")

    except Exception as e:
        print("OAUTH ERROR:", str(e))

        return JSONResponse(
            {"error": str(e)},
            status_code=500,
        )

@app.get("/result")
def get_result(creds=Depends(get_current_user)):
    service = build("gmail", "v1", credentials=creds)
    results = service.users().messages().list(userId="me", maxResults=30).execute()
    messages = results.get("messages", [])

    print("GMAIL MESSAGES FOUND:", len(messages))

    extracted = []
    sender_counter = collections.defaultdict(int)

    for msg in messages:
        try:
            data = service.users().messages().get(
                userId="me",
                id=msg["id"],
                format="metadata",
                metadataHeaders=["From", "Subject"]
            ).execute()

            snippet = service.users().messages().get(
                userId="me",
                id=msg["id"],
                format="minimal"
            ).execute().get("snippet", "")

            sub = next(
                (h["value"] for h in data.get("payload", {}).get("headers", []) if h["name"] == "Subject"),
                "(No Subject)"
            )
            sender = next(
                (h["value"] for h in data.get("payload", {}).get("headers", []) if h["name"] == "From"),
                "Unknown"
            )
            sender_simple = sender.split("<")[0].strip().replace('"', '')
            sender_counter[sender_simple] += 1

            extracted.append({
                "id": msg["id"],
                "from": sender_simple,
                "subject": sub,
                "snippet": snippet
            })
        except Exception as e:
            print("EMAIL EXTRACT ERROR:", e)
            continue

    for e in extracted:
        e["sender_count"] = sender_counter[e["from"]]

    print("EXTRACTED EMAILS:", len(extracted))

    categories = categorize_with_ai(extracted)

    counts = {
        "Action Items": len(categories.get("Action Items", [])),
        "Applications": len(categories.get("Applications", [])),
        "University": len(categories.get("University", [])),
        "Promotions": len(categories.get("Promotions", [])),
    }

    return {
        "status": "success",
        "counts": counts,
        "categories": categories,
        "emails": extracted
    }

@app.get("/action/trash/{msg_id}")
def trash_email(msg_id: str, creds = Depends(get_current_user)):
    try:
        build("gmail", "v1", credentials=creds).users().messages().trash(userId="me", id=msg_id).execute()
        return {"status": "success"}
    except Exception as e: return JSONResponse({"error": str(e)}, status_code=500)

# ✅ NEW: GENERATE DRAFT (PREVIEW)
@app.post("/action/generate_reply")
def generate_reply(request: GenerateRequest, creds = Depends(get_current_user)):
    try:
        service = build("gmail", "v1", credentials=creds)
        msg = service.users().messages().get(userId="me", id=request.msg_id, format="full").execute()
        snippet = msg.get("snippet", "")
        
        prompt = f"""
        You are a professional email assistant.
        Incoming Snippet: "{snippet}"
        USER INSTRUCTION: "{request.intent}"
        Task: Write a polite, concise email reply. Use the instruction. No placeholders.
        """
        completion = client.chat.completions.create(model=GROQ_MODEL, messages=[{"role": "user", "content": prompt}], temperature=0.7)
        return {"status": "success", "reply": completion.choices[0].message.content}
    except Exception as e: return JSONResponse({"error": str(e)}, status_code=500)

# ✅ NEW: SEND CUSTOM REPLY
@app.post("/action/send_custom")
def send_custom(request: SendRequest, creds = Depends(get_current_user)):
    try:
        service = build("gmail", "v1", credentials=creds)
        msg = service.users().messages().get(userId="me", id=request.msg_id, format="metadata").execute()
        headers = msg["payload"]["headers"]
        subject = next((h["value"] for h in headers if h["name"] == "Subject"), "No Subject")
        sender = next((h["value"] for h in headers if h["name"] == "From"), "")
        
        reply_subject = f"Re: {subject}" if not subject.startswith("Re:") else subject
        sender_email = sender.split("<")[1].strip(">") if "<" in sender else sender
        
        message = create_message(sender_email, reply_subject, request.body)
        service.users().messages().send(userId="me", body=message).execute()
        return {"status": "success"}
    except Exception as e: return JSONResponse({"error": str(e)}, status_code=500)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

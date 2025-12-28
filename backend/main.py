import os
import json
import logging
import collections
from fastapi import FastAPI, Request, Response, Depends, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse
from dotenv import load_dotenv
from groq import Groq
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from sqlalchemy import create_engine, Column, String, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from starlette.config import Config
from starlette.datastructures import Secret

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- CONFIGURATION ---
GROQ_MODEL = "llama-3.1-8b-instant"
CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
REDIRECT_URI = "https://inbox-intelligence.onrender.com/auth/callback" # Update if local
FRONTEND_URL = "https://inbox-intelligence.streamlit.app"

# Database Config (Default to SQLite if no DB URL found, for safety)
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./test.db")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# Secret key for signing cookies (Make sure to set this in Render Env Vars later!)
SECRET_KEY = os.getenv("SECRET_KEY", "super-secret-dev-key")

# --- DATABASE SETUP ---
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# 1. The User Table
class User(Base):
    __tablename__ = "users"
    email = Column(String, primary_key=True, index=True)
    credentials_json = Column(Text) # Storing the full credentials object as JSON

# Create tables
Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

app = FastAPI(title="Inbox Intelligence Backend")
client = Groq(api_key=os.getenv("GROQ_API_KEY"))

# --- OAUTH HELPERS ---
def create_flow():
    return Flow.from_client_config(
        {
            "web": {
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": [REDIRECT_URI],
            }
        },
        scopes=["https://www.googleapis.com/auth/gmail.modify"],
        redirect_uri=REDIRECT_URI,
    )

def get_current_user(request: Request, db: Session = Depends(get_db)):
    # 2. Secure Session Check
    user_email = request.cookies.get("user_email")
    if not user_email:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    user = db.query(User).filter(User.email == user_email).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    
    # Rebuild credentials object from stored JSON
    creds_data = json.loads(user.credentials_json)
    creds = Credentials.from_authorized_user_info(creds_data)
    return creds

# --- AI LOGIC (Unchanged) ---
def categorize_with_ai(emails):
    if not emails: return {}
    # ... (Keep your exact AI logic from previous code here) ...
    # For brevity, I am not repeating the whole AI block, paste it here.
    return {"🚨 Action Required": emails} # Placeholder if you don't paste the AI code back

# --- ROUTES ---

@app.get("/")
def home():
    return {"message": "Inbox Intelligence Backend (Multi-User) is Online"}

@app.get("/auth/login")
def login():
    flow = create_flow()
    auth_url, _ = flow.authorization_url(prompt="consent", access_type="offline") 
    # access_type="offline" is CRITICAL to get a refresh_token for long-term access
    return RedirectResponse(auth_url)

@app.get("/auth/callback")
def callback(request: Request, response: Response, db: Session = Depends(get_db)):
    try:
        auth_response = str(request.url).replace("http:", "https:", 1) if "onrender" in str(request.url) else str(request.url)
        
        flow = create_flow()
        flow.fetch_token(authorization_response=auth_response)
        creds = flow.credentials

        # Get user email to use as ID
        service = build("gmail", "v1", credentials=creds)
        profile = service.users().getProfile(userId="me").execute()
        email = profile["emailAddress"]

        # 3. Save User to DB
        creds_json = creds.to_json()
        db_user = db.query(User).filter(User.email == email).first()
        if not db_user:
            db_user = User(email=email, credentials_json=creds_json)
            db.add(db_user)
        else:
            db_user.credentials_json = creds_json # Update tokens
        db.commit()

        # 4. Set Session Cookie (Simple email cookie for now)
        # In production, use a signed/encrypted session token
        response = RedirectResponse(FRONTEND_URL)
        response.set_cookie(key="user_email", value=email, max_age=604800, httponly=True, samesite="none", secure=True)
        return response

    except Exception as e:
        logger.error(f"Error: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)

@app.get("/result")
def get_result(request: Request, db: Session = Depends(get_db)):
    # Authenticate via DB
    try:
        creds = get_current_user(request, db)
    except HTTPException:
        return {"status": "error", "message": "Login required"}

    # Fetch Emails (Same logic as before, just using 'creds')
    service = build("gmail", "v1", credentials=creds)
    results = service.users().messages().list(userId="me", maxResults=20).execute()
    messages = results.get("messages", [])
    
    extracted_emails = []
    # ... (Paste your email extraction loop here) ...
    # For now, returning empty to verify DB works
    
    # Real app: return {"status": "success", "categories": categorize_with_ai(extracted_emails)}
    return {"status": "success", "categories": {}} 

@app.get("/action/trash/{msg_id}")
def trash_email(msg_id: str, request: Request, db: Session = Depends(get_db)):
    try:
        creds = get_current_user(request, db)
        service = build("gmail", "v1", credentials=creds)
        service.users().messages().trash(userId="me", id=msg_id).execute()
        return {"status": "success", "id": msg_id}
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

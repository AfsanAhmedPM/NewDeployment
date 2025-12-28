import os
import json
import logging
import uuid
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
# Update this to your Live Backend URL
REDIRECT_URI = "https://inbox-intelligence.onrender.com/auth/callback"
FRONTEND_URL = "https://inbox-intelligence.streamlit.app"

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./test.db")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# --- DATABASE ---
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    email = Column(String, primary_key=True, index=True)
    credentials_json = Column(Text)
    session_token = Column(String, index=True) # ✅ NEW: Token for Streamlit

Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

app = FastAPI()
client = Groq(api_key=os.getenv("GROQ_API_KEY"))
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# --- AUTH HELPERS ---
def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    # 1. Look up user by the token passed in the Header
    user = db.query(User).filter(User.session_token == token).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid Session")
    
    creds_data = json.loads(user.credentials_json)
    return Credentials.from_authorized_user_info(creds_data)

def create_flow():
    return Flow.from_client_config(
        {
            "web": {
                "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": [REDIRECT_URI],
            }
        },
        scopes=["https://www.googleapis.com/auth/gmail.modify"],
        redirect_uri=REDIRECT_URI,
    )

# --- ROUTES ---
@app.get("/")
def home(): return {"status": "Multi-User Backend Online"}

@app.get("/auth/login")
def login():
    flow = create_flow()
    auth_url, _ = flow.authorization_url(prompt="consent", access_type="offline")
    return RedirectResponse(auth_url)

@app.get("/auth/callback")
def callback(request: Request, db: Session = Depends(get_db)):
    try:
        auth_response = str(request.url).replace("http:", "https:", 1)
        flow = create_flow()
        flow.fetch_token(authorization_response=auth_response)
        creds = flow.credentials

        service = build("gmail", "v1", credentials=creds)
        email = service.users().getProfile(userId="me").execute()["emailAddress"]

        # Generate a new session token
        new_token = str(uuid.uuid4())

        # Save/Update User in DB
        user = db.query(User).filter(User.email == email).first()
        if not user:
            user = User(email=email, credentials_json=creds.to_json(), session_token=new_token)
            db.add(user)
        else:
            user.credentials_json = creds.to_json()
            user.session_token = new_token
        
        db.commit()

        # ✅ Redirect to Frontend WITH the token in URL
        return RedirectResponse(f"{FRONTEND_URL}?token={new_token}")

    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)

@app.get("/result")
def get_result(creds = Depends(get_current_user)): # ✅ Requires Token
    # Fetch Emails
    service = build("gmail", "v1", credentials=creds)
    results = service.users().messages().list(userId="me", maxResults=15).execute()
    messages = results.get("messages", [])
    
    # ... (Insert your Email Extraction + AI Logic here) ...
    # For testing, we just return the raw list to prove auth works
    return {"status": "success", "categories": {"📥 Recent Emails": messages}}

@app.get("/action/trash/{msg_id}")
def trash_email(msg_id: str, creds = Depends(get_current_user)): # ✅ Requires Token
    try:
        service = build("gmail", "v1", credentials=creds)
        service.users().messages().trash(userId="me", id=msg_id).execute()
        return {"status": "success", "id": msg_id}
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

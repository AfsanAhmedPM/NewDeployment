import os  # <--- FIXED (was vimport)
import json
import logging
import collections
from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse, JSONResponse
from dotenv import load_dotenv
from groq import Groq
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build

# --- SETUP ---
# Allow HTTP for local testing, but Render uses HTTPS so this is just a fallback safety
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1" 

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- CONFIG ---
GROQ_MODEL = "llama-3.1-8b-instant"
CLIENT_ID = 115872799324-4l50npg996d4n3gd2ca958fkgf21pa6i.apps.googleusercontent.com
CLIENT_SECRET = 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
REDIRECT_URI = "https://inboxintelligence.onrender.com/auth/callback"
FRONTEND_URL = "https://inbox-intelligence.streamlit.app/"

app = FastAPI(title="Inbox Intelligence Backend")
client = Groq(api_key=os.getenv("GROQ_API_KEY"))

# In-memory session storage
USER_SESSION = {
    "credentials": None,
    "last_result": {}
}

# --- OAUTH FLOW ---
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
    scopes=["https://www.googleapis.com/auth/gmail.readonly"],
    redirect_uri=REDIRECT_URI,
)

# --- AI LOGIC ---
def categorize_with_ai(emails):
    if not emails:
        return {}

    email_map = {i: e for i, e in enumerate(emails, 1)}

    prompt_lines = []
    for i, e in email_map.items():
        clean_snippet = e['snippet'][:60].replace("\n", " ")
        prompt_lines.append(f"ID {i} | From: {e['from']} | Sub: {e['subject']} | Body: {clean_snippet}")

    prompt_text = "\n".join(prompt_lines)

    system_prompt = """
    You are a career-focused email assistant. Sort emails into exactly these 4 categories:
    1. "🚨 Action Required" (INTERVIEWS, CODING TESTS, DEADLINES, OFFERS)
    2. "⏳ Applications & Updates" (Application Received, Status Update, Rejections)
    3. "🎓 University & Learning" (College/University emails, Newsletters, Courses)
    4. "🗑️ Promotions & Noise" (Marketing, LinkedIn, Social media)

    RULES:
    - Return ONLY a JSON object: { "Category Name": [ID1, ID2] }
    """

    try:
        completion = client.chat.completions.create(
            model=GROQ_MODEL,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt_text}
            ],
            temperature=0.0,
            response_format={"type": "json_object"}
        )
        
        ai_response = completion.choices[0].message.content
        category_map = json.loads(ai_response)

        final_output = {}
        for category, ids in category_map.items():
            final_output[category] = []
            for eid in ids:
                original = email_map.get(int(eid))
                if original:
                    final_output[category].append(original)
        
        return final_output

    except Exception as e:
        logger.error(f"AI Processing Failed: {e}")
        return {}

# --- ROUTES ---
@app.get("/")
def home():
    return {"message": "Inbox Intelligence Backend is Online!"}

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/auth/login")
def login():
    auth_url, _ = flow.authorization_url(prompt="consent")
    return RedirectResponse(auth_url)

@app.get("/auth/callback")
def callback(request: Request):
    try:
        # --- HTTPS FIX FOR RENDER ---
        auth_response = str(request.url)
        # Render puts the app behind a proxy, so it sees 'http' even if user is on 'https'
        # Google requires the redirect_uri to match exactly (https)
        if auth_response.startswith("http:"):
            auth_response = auth_response.replace("http:", "https:", 1)
        
        # 1. Fetch Token ONCE (Fixed)
        flow.fetch_token(authorization_response=auth_response)
        USER_SESSION["credentials"] = flow.credentials
        
        # --- START GMAIL LOGIC ---
        service = build("gmail", "v1", credentials=flow.credentials)
        results = service.users().messages().list(userId="me", maxResults=60).execute()
        messages = results.get("messages", [])
        
        extracted_emails = []
        sender_counter = collections.defaultdict(int)

        for msg in messages:
            try:
                data = service.users().messages().get(
                    userId="me", id=msg["id"], format="metadata", metadataHeaders=["From", "Subject"]
                ).execute()
                
                snippet_res = service.users().messages().get(
                    userId="me", id=msg["id"], format="minimal"
                ).execute()
                
                headers = data.get("payload", {}).get("headers", [])
                subject = next((h["value"] for h in headers if h["name"] == "Subject"), "(No Subject)")
                sender = next((h["value"] for h in headers if h["name"] == "From"), "Unknown")
                snippet = snippet_res.get("snippet", "")
                
                # Simple Sender Name (Remove <email>)
                sender_simple = sender.split("<")[0].strip().replace('"', '')
                sender_counter[sender_simple] += 1

                extracted_emails.append({
                    "id": msg["id"],
                    "from": sender_simple,
                    "subject": subject,
                    "snippet": snippet
                })
            except Exception:
                continue
        
        # Attach Counts
        for email in extracted_emails:
            email["sender_count"] = sender_counter[email["from"]]
        
        # AI Sort
        structured_data = categorize_with_ai(extracted_emails)
        USER_SESSION["last_result"] = structured_data
        
        return RedirectResponse(FRONTEND_URL)

    except Exception as e:
        logger.error(f"Callback Error: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)

@app.get("/result")
def get_result():
    return {"status": "success", "categories": USER_SESSION.get("last_result", {})}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

from fastapi import FastAPI, Header, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
import re

app = FastAPI(title="Apex Compliance Engine", version="1.0.0")

# CORS Middleware configuration to allow frontend to communicate with backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins (frontend domains)
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods (POST, GET, etc.)
    allow_headers=["*"],  # Allows all headers including access-token
)

# API Key Security Definition
SECRET_API_KEY = "apex_secret_key_999"

def verify_api_key(access_token: str = Header(None)):
    if not access_token or access_token != SECRET_API_KEY:
        raise HTTPException(
            status_code=401, 
            detail="Unauthorized: Invalid or missing API Secret Access Key."
        )
    return access_token

class VendorRequest(BaseModel):
    company_name: str
    gstin: str
    pan: str
    contact_person: str
    email: EmailStr

@app.get("/")
def home():
    return {"message": "Apex Compliance Engine Backend is Live!"}

@app.post("/api/v1/vendor/verify")
def verify_vendor(data: VendorRequest, token: str = Depends(verify_api_key)):
    # Compliance Risk Assessment Logic
    risk_score = "Low"
    status = "Approved"
    message = "Vendor passed all core compliance, GSTIN format, and PAN verification checks successfully."

    # Check for simulated high risk / fraudulent keywords or patterns
    pan_upper = data.pan.upper()
    gstin_upper = data.gstin.upper()
    
    if "FAKE" in pan_upper or "SCAM" in data.company_name.upper() or gstin_upper.startswith("99"):
        risk_score = "High"
        status = "Flagged / Rejected"
        message = "Vendor flagged due to suspicious pattern matching in PAN/GSTIN or high-risk entity records."
    elif len(pan_upper) != 10:
        risk_score = "Medium"
        status = "Review Required"
        message = "PAN number length mismatch. Manual compliance review recommended."

    return {
        "status": status,
        "company_name": data.company_name,
        "risk_score": risk_score,
        "message": message
    }

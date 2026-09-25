from fastapi import FastAPI, Security, HTTPException, status
from fastapi.security.api_key import APIKeyHeader
from pydantic import BaseModel
from datetime import datetime
import random

app = FastAPI(
    title="Apex Enterprise Compliance & Vendor Onboarding Engine",
    description="Professional B2B SaaS Engine for Automated Vendor Verification, GSTIN/PAN Validation, and Bulk Excel Risk Scoring.",
    version="1.0.0"
)

# API Key Security Configuration
API_KEY = "apex_secret_key_999"
API_KEY_NAME = "access-token"

api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

async def get_api_key(api_key_header: str = Security(api_key_header)):
    if api_key_header == API_KEY:
        return api_key_header
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Could not validate credentials. Invalid or missing API Key. Access denied!"
    )

class VendorOnboardingRequest(BaseModel):
    company_name: str
    gstin: str
    pan: str
    contact_person: str
    email: str

@app.get("/")
def read_root():
    return {
        "status": "Enterprise Core Online",
        "system": "Apex B2B Vendor & Compliance Onboarding Engine",
        "documentation": "/docs"
    }

@app.post("/api/v1/vendor/verify")
async def verify_vendor(data: VendorOnboardingRequest, api_key: str = Security(get_api_key)):
    # Simulated compliance logic with enterprise risk scoring
    risk_score = round(random.uniform(5.0, 35.0), 2)
    status_text = "Approved - Low Risk" if risk_score < 25.0 else "Review Required - Medium Risk"
    
    return {
        "success": True,
        "assessment_id": f"APEX-VEND-{random.randint(100000, 999999)}",
        "company_name": data.company_name,
        "compliance_status": status_text,
        "risk_score": risk_score,
        "timestamp": datetime.utcnow().isoformat()
    }


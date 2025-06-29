from fastapi import FastAPI, APIRouter, HTTPException
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field
from typing import List, Dict, Any
import uuid
from datetime import datetime
import re
import asyncio
from emergentintegrations.llm.chat import LlmChat, UserMessage

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Create the main app without a prefix
app = FastAPI(title="SecureMail API", description="AI-Based Email Threat Detector")

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Define Models
class EmailAnalysisRequest(BaseModel):
    email_content: str
    session_id: str = Field(default_factory=lambda: str(uuid.uuid4()))

class ThreatDetection(BaseModel):
    text: str
    threat_type: str
    confidence: int
    start_pos: int
    end_pos: int
    description: str

class EmailAnalysisResult(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str
    email_content: str
    overall_threat_score: int
    threat_level: str  # LOW, MEDIUM, HIGH, CRITICAL
    threats_detected: List[ThreatDetection]
    analysis_summary: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class PhishingReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    analysis_id: str
    email_content: str
    threat_score: int
    user_notes: str = ""
    timestamp: datetime = Field(default_factory=datetime.utcnow)

# AI Analysis Function
async def analyze_email_threats(email_content: str, session_id: str) -> EmailAnalysisResult:
    """Analyze email content for threats using OpenAI GPT-4o"""
    try:
        # Initialize OpenAI chat
        chat = LlmChat(
            api_key=os.environ.get('OPENAI_API_KEY'),
            session_id=session_id,
            system_message="""You are an expert email security analyst. Analyze email content for:
1. Phishing attempts
2. Scam indicators
3. Malicious links
4. Social engineering tactics
5. Urgency manipulation
6. Suspicious attachments mentions
7. Impersonation attempts

For each threat found, provide:
- Exact text snippet
- Threat type
- Confidence score (0-100)
- Position in text (character start/end)
- Brief description

Format your response as JSON with this structure:
{
    "overall_threat_score": 85,
    "threat_level": "HIGH",
    "threats_detected": [
        {
            "text": "exact threatening text",
            "threat_type": "PHISHING_LINK",
            "confidence": 95,
            "start_pos": 120,
            "end_pos": 145,
            "description": "Suspicious URL mimicking legitimate site"
        }
    ],
    "analysis_summary": "Brief summary of findings"
}

Threat levels: LOW (0-25), MEDIUM (26-50), HIGH (51-75), CRITICAL (76-100)"""
        ).with_model("openai", "gpt-4o")

        # Create analysis prompt
        user_message = UserMessage(
            text=f"Analyze this email for security threats:\n\n{email_content}\n\nProvide detailed threat analysis in the specified JSON format."
        )

        # Get AI response
        response = await chat.send_message(user_message)
        
        # Parse the JSON response
        import json
        try:
            analysis_data = json.loads(response)
        except json.JSONDecodeError:
            # Fallback parsing if JSON is wrapped in markdown
            json_start = response.find('{')
            json_end = response.rfind('}') + 1
            if json_start != -1 and json_end != -1:
                analysis_data = json.loads(response[json_start:json_end])
            else:
                raise HTTPException(status_code=500, detail="Failed to parse AI response")

        # Create threat detection objects
        threats = []
        for threat in analysis_data.get('threats_detected', []):
            threats.append(ThreatDetection(**threat))

        # Create analysis result
        result = EmailAnalysisResult(
            session_id=session_id,
            email_content=email_content,
            overall_threat_score=analysis_data.get('overall_threat_score', 0),
            threat_level=analysis_data.get('threat_level', 'LOW'),
            threats_detected=threats,
            analysis_summary=analysis_data.get('analysis_summary', 'Analysis completed')
        )

        # Store in database
        await db.email_analyses.insert_one(result.dict())
        
        return result

    except Exception as e:
        logging.error(f"Error analyzing email: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

# API Routes
@api_router.get("/")
async def root():
    return {"message": "SecureMail API - AI Email Threat Detector"}

@api_router.post("/analyze-email", response_model=EmailAnalysisResult)
async def analyze_email(request: EmailAnalysisRequest):
    """Analyze email content for security threats"""
    if not request.email_content.strip():
        raise HTTPException(status_code=400, detail="Email content cannot be empty")
    
    result = await analyze_email_threats(request.email_content, request.session_id)
    return result

@api_router.get("/analysis/{analysis_id}", response_model=EmailAnalysisResult)
async def get_analysis(analysis_id: str):
    """Get analysis by ID"""
    analysis = await db.email_analyses.find_one({"id": analysis_id})
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return EmailAnalysisResult(**analysis)

@api_router.get("/analyses", response_model=List[EmailAnalysisResult])
async def get_analyses(limit: int = 50):
    """Get recent analyses"""
    analyses = await db.email_analyses.find().sort("timestamp", -1).limit(limit).to_list(limit)
    return [EmailAnalysisResult(**analysis) for analysis in analyses]

@api_router.post("/report-phishing", response_model=PhishingReport)
async def report_phishing(analysis_id: str, user_notes: str = ""):
    """Report a phishing email"""
    # Get the analysis
    analysis = await db.email_analyses.find_one({"id": analysis_id})
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    
    # Create report
    report = PhishingReport(
        analysis_id=analysis_id,
        email_content=analysis['email_content'],
        threat_score=analysis['overall_threat_score'],
        user_notes=user_notes
    )
    
    # Store report
    await db.phishing_reports.insert_one(report.dict())
    return report

@api_router.get("/reports", response_model=List[PhishingReport])
async def get_reports():
    """Get all phishing reports"""
    reports = await db.phishing_reports.find().sort("timestamp", -1).to_list(100)
    return [PhishingReport(**report) for report in reports]

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
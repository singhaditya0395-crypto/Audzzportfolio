from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
import uvicorn

app = FastAPI(title="Aditya Singh Portfolio API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
);

class MeetingRequest(BaseModel):
    topic: str
    name: str
    email: EmailStr
    organization: str
    role: str
    notes: str

@app.get("/api/health")
def health_check():
    return {"status": "healthy", "service": "python-backend-engine"}

@app.post("/api/meetings")
def create_meeting(data: MeetingRequest):
    # Process or store questionnaire data securely
    print(f"[API] Meeting questionnaire received from {data.name} ({data.organization}) for topic: {data.topic}")
    return {
        "success": True,
        "message": "Questionnaire saved successfully. Proceeding to calendar schedule.",
        - "submitted_data": data.dict()
    }

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
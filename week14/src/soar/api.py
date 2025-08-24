from fastapi import FastAPI
from pydantic import BaseModel
import asyncio, os
from .detection.threat_detector import ThreatDetector
from .analysis.incident_analyzer import IncidentAnalyzer
from .response.automated_responder import AutomatedResponder
from .prediction.threat_predictor import ThreatPredictor
from .core.handler import IncidentHandler

app = FastAPI(title="SOAR API")
handler = IncidentHandler(ThreatDetector(), IncidentAnalyzer(), AutomatedResponder(), ThreatPredictor())

class Event(BaseModel): event: dict

@app.post("/events")
async def post_event(ev: Event):
    return await handler.handle_incident(ev.event)

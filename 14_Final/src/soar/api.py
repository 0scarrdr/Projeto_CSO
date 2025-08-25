from fastapi import FastAPI, Response
from pydantic import BaseModel
from prometheus_client import generate_latest
import asyncio, os
from .detection.threat_detector import ThreatDetector
from .analysis.incident_analyzer import IncidentAnalyzer
from .response.automated_responder import AutomatedResponder
from .prediction.threat_predictor import ThreatPredictor
from .core.handler import IncidentHandler

app = FastAPI(title="SOAR API")
handler = IncidentHandler()

class Event(BaseModel): event: dict

@app.post("/events")
async def ingest_event(event: dict):
    return await handler.handle_incident(event)


@app.get("/metrics")
async def metrics():
    return Response(generate_latest(), media_type="text/plain")
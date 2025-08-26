from fastapi import FastAPI, Response
import logging
from pydantic import BaseModel
from prometheus_client import generate_latest
import asyncio, os
from soar.detection.threat_detector import ThreatDetector
from soar.analysis.incident_analyzer import IncidentAnalyzer
from soar.response.automated_responder import AutomatedResponder
from soar.prediction.threat_predictor import ThreatPredictor
from soar.core.handler import IncidentHandler


app = FastAPI(title="SOAR API")
handler = IncidentHandler()
logger = logging.getLogger("api")

class Event(BaseModel):
    id: str
    type: str
    severity: str
    src_ip: str
    business_critical: bool

@app.post("/events")
async def ingest_event(event: Event):
    try:
        return await handler.handle_incident(event.dict())
    except Exception as e:
        logger.exception(f"Erro ao processar evento: {e}")
        return Response(content=f"Internal Server Error: {e}", status_code=500)

@app.get("/metrics")
async def metrics():
    return Response(generate_latest(), media_type="text/plain")
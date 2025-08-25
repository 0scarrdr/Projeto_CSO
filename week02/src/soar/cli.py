import json, asyncio
import typer
from .core.handler import IncidentHandler, ThreatDetectorIFace, IncidentAnalyzerIFace, AutomatedResponderIFace, ThreatPredictorIFace
from .core.incident import Incident
from datetime import datetime
import uuid

# implementations to prove the flow (Week 2 only)
class DummyDetector(ThreatDetectorIFace):
    def classify(self, event: dict):
        if "message" in event:
            return Incident(str(uuid.uuid4()), "dummy", "low", "log", datetime.utcnow(), attributes=event)
        return None
class DummyAnalyzer(IncidentAnalyzerIFace):
    async def deep_analysis(self, incident: Incident): return {"risk_score": 0.1}
class DummyResponder(AutomatedResponderIFace):
    async def execute_playbook(self, incident: Incident): return {"status": "noop"}
class DummyPredictor(ThreatPredictorIFace):
    async def forecast_related_threats(self, incident: Incident): return {"top_related": {"dummy": 1.0}}

app = typer.Typer(no_args_is_help=True)

@app.command()
def demo(event: str = typer.Option("{"message":"hello"}", help="JSON event string")):
    async def run():
        import json as _json
        handler = IncidentHandler(DummyDetector(), DummyAnalyzer(), DummyResponder(), DummyPredictor())
        res = await handler.handle_incident(_json.loads(event))
        typer.echo(_json.dumps(res, indent=2, default=str))
    asyncio.run(run())

if __name__ == "__main__":
    app()

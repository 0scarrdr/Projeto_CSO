import json, asyncio
from pathlib import Path
from soar.core.handler import IncidentHandler
from soar.detection.threat_detector import ThreatDetector
from soar.analysis.incident_analyzer import IncidentAnalyzer
from soar.response.automated_responder import AutomatedResponder
from soar.prediction.threat_predictor import ThreatPredictor

def test_demo_events():
    async def run():
        handler = IncidentHandler(ThreatDetector(), IncidentAnalyzer(), AutomatedResponder(), ThreatPredictor())
        path = Path("tests/data/events.jsonl")
        ok = []
        with path.open() as f:
            for line in f:
                res = await handler.handle_incident(json.loads(line))
                ok.append(res["response"]["status"] == "completed")
        assert all(ok)
    asyncio.run(run())

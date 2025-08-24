import json, asyncio
import typer
from .detection.threat_detector import ThreatDetector
from .analysis.incident_analyzer import IncidentAnalyzer
from .response.automated_responder import AutomatedResponder
from .prediction.threat_predictor import ThreatPredictor
from .core.handler import IncidentHandler

app = typer.Typer(no_args_is_help=True)

@app.command()
def demo(events: str):
    async def run():
        handler = IncidentHandler(ThreatDetector(), IncidentAnalyzer(), AutomatedResponder(), ThreatPredictor())
        with open(events, "r", encoding="utf-8") as f:
            for line in f:
                event = json.loads(line.strip())
                res = await handler.handle_incident(event)
                typer.echo(json.dumps(res, indent=2, default=str))
    asyncio.run(run())

if __name__ == "__main__":
    app()

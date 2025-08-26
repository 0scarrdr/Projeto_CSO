
"""
Threat predictor with optional ML support.
Fallback to frequency-based predictions if no model is available.
"""

import pickle
from collections import deque, Counter
from pathlib import Path
from soar.utils.logging import get_logger
from soar.analysis.ml_model import IncidentMLModel

logger = get_logger(__name__)

MODEL_PATH = Path(__file__).parent.parent.parent / ".model" / "threat_predictor.pkl"

class ThreatPredictor:
    def __init__(self, window_size=100):
        self.recent_incidents = deque(maxlen=window_size)
        self.model = None
        self.ml_model = None
        self._load_model()

    def _load_model(self):
        if MODEL_PATH.exists():
            try:
                with open(MODEL_PATH, "rb") as f:
                    self.model = pickle.load(f)
                logger.info(f"Modelo ML carregado de {MODEL_PATH}")
            except Exception as e:
                logger.error(f"Falha a carregar modelo ML: {e}")

    def update_window(self, incident_type: str):
        self.recent_incidents.append(incident_type)

    def predict_related(self, current_incident: dict) -> dict:
        """
        If model exists, predict with ML.
        Otherwise, fallback to simple frequency count.
        """
        incident_type = current_incident.get("type")
        self.update_window(incident_type)

        # Tenta prever com ML se o modelo existir
        if self.model:
            try:
                features = [[len(self.recent_incidents)]]
                pred = self.model.predict(features)[0]
                return {"likely_next": pred, "method": "ml"}
            except Exception as e:
                logger.error(f"Erro a prever com modelo ML: {e}")

        # fallback: frequência
        counter = Counter(self.recent_incidents)
        most_common = counter.most_common(2)
        return {"likely_next": [x for x, _ in most_common], "method": "frequency"}

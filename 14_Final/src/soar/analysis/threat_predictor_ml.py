from sklearn.ensemble import RandomForestClassifier
import numpy as np
import pickle
from soar.utils.logging import get_logger

logger = get_logger(__name__)
MODEL_PATH = "model_rf.pkl"

class ThreatPredictorML:
    def __init__(self):
        if os.path.exists(MODEL_PATH):
            with open(MODEL_PATH, "rb") as f:
                self.model = pickle.load(f)
        else:
            self.model = RandomForestClassifier()
    def train(self, X, y):
        self.model.fit(X, y)
        with open(MODEL_PATH, "wb") as f:
            pickle.dump(self.model, f)
    def predict(self, features):
        try:
            pred = self.model.predict(np.array(features).reshape(1, -1))
            logger.info(f"Previsão ML: {pred}")
            return pred[0]
        except Exception as e:
            logger.error(f"Erro na previsão ML: {e}")
            return None

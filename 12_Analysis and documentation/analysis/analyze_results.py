# Loads SIEM outbox and metrics to compute simple KPIs and a confusion matrix mock
import json, pandas as pd, numpy as np, sys
from pathlib import Path

e = Path(".outbox/siem_events.jsonl")
m = Path(".outbox/metrics.csv")
events = [json.loads(l) for l in e.read_text().splitlines()] if e.exists() else []
dfm = pd.read_csv(m, header=None, names=["kind","name","value","ts"]) if m.exists() else pd.DataFrame()

print("Events to SIEM:", len(events))
if not dfm.empty:
    print(dfm.groupby(["kind","name"])["value"].describe())
else:
    print("No metrics yet")
# Mock confusion matrix computation
y_true = np.array([1,0,1,1,0,0,1,0])
y_pred = np.array([1,0,1,0,0,0,1,0])
from sklearn.metrics import confusion_matrix, accuracy_score
cm = confusion_matrix(y_true, y_pred)
print("Accuracy:", accuracy_score(y_true, y_pred))
print("Confusion matrix:\n", cm)

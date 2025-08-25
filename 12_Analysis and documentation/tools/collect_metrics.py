# Usage: python tools/collect_metrics.py .outbox/metrics.csv
import sys, pandas as pd
path = sys.argv[1] if len(sys.argv)>1 else ".outbox/metrics.csv"
df = pd.read_csv(path, header=None, names=["kind","name","value","ts"])
print(df.groupby(["kind","name"])["value"].describe())

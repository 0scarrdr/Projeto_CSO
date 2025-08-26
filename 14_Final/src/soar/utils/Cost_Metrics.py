import json
import os
from soar.utils.logging import logger

COST_LOG = "cost_metrics.jsonl"

def log_cost(event_type, resource_usage, cost_value):
    entry = {
        "event_type": event_type,
        "resource_usage": resource_usage,
        "cost_value": cost_value
    }
    with open(COST_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")
    logger.info(f"[CostMetrics] Logged cost for {event_type}: {cost_value}")

def summarize_costs():
    if not os.path.exists(COST_LOG):
        logger.warning("[CostMetrics] No cost metrics found.")
        return {}
    total_cost = 0
    with open(COST_LOG) as f:
        for line in f:
            entry = json.loads(line)
            total_cost += entry["cost_value"]
    logger.info(f"[CostMetrics] Total cost: {total_cost}")
    return {"total_cost": total_cost}
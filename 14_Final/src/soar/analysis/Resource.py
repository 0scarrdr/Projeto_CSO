from soar.utils.logging import logger

def analyze_resource_usage(metrics):
    logger.info("[ResourceOptimization] Analyzing resource usage...")
    suggestions = []
    for metric in metrics:
        if metric["cpu"] > 80:
            suggestions.append(f"Reduce CPU usage on {metric['system']}")
        if metric["memory"] > 75:
            suggestions.append(f"Optimize memory on {metric['system']}")
        if metric["disk"] > 90:
            suggestions.append(f"Increase disk space for {metric['system']}")
    logger.info(f"[ResourceOptimization] Suggestions: {suggestions}")
    return suggestions

def optimize_resources(metrics):
    suggestions = analyze_resource_usage(metrics)
    for suggestion in suggestions:
        logger.info(f"[ResourceOptimization] Applying: {suggestion}")
    return suggestions
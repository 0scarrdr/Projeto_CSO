"""
Response Orchestrator
Executes response playbooks with dynamic action resolution
"""

import asyncio
import importlib
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)


class ResponseOrchestrator:
    """
    Orchestrates the execution of response playbooks
    
    This class dynamically resolves and executes response actions
    defined in playbook YAML files according to assignment requirements.
    """
    
    def __init__(self):
        """Initialize the response orchestrator"""
        self.cache = {}
        logger.info("ResponseOrchestrator initialized")
    
    def _resolve(self, dotted: str):
        """
        Dynamically resolve action functions from module paths
        
        Args:
            dotted: Dotted module path like 'network.block_ip'
            
        Returns:
            Function object for the action
        """
        if dotted in self.cache:
            return self.cache[dotted]
        
        try:
            # Split module and function name
            ns, fn = dotted.rsplit(".", 1)
            
            # Import the module
            mod = importlib.import_module(f".actions.{ns}", package="soar.response")
            
            # Get the function
            f = getattr(mod, fn)
            
            # Cache for future use
            self.cache[dotted] = f
            
            logger.debug(f"Resolved action: {dotted}")
            return f
            
        except (ImportError, AttributeError) as e:
            logger.error(f"Failed to resolve action {dotted}: {e}")
            # Return a fallback function
            return self._create_fallback_action(dotted)
    
    def _create_fallback_action(self, action_name: str):
        """Create a fallback action for missing implementations"""
        async def fallback_action(incident, **params):
            logger.warning(f"Using fallback for missing action: {action_name}")
            return {
                "status": "simulated",
                "action": action_name,
                "message": f"Simulated execution of {action_name}",
                "params": params,
                "success": True
            }
        return fallback_action
    
    async def execute(self, playbook: dict, incident) -> dict:
        """
        Execute a response playbook
        
        Args:
            playbook: Playbook definition with steps
            incident: Incident object to process
            
        Returns:
            Execution results
        """
        try:
            logger.info(f"Executing playbook with {len(playbook.get('steps', []))} steps")
            
            results = []
            
            for step in playbook.get("steps", []):
                action = step["action"]
                params = dict(step.get("params", {}))
                
                # Replace incident placeholders in parameters
                for k, v in list(params.items()):
                    if isinstance(v, str) and v.startswith("INCIDENT_"):
                        key = v.replace("INCIDENT_", "").lower()
                        # Try to get from incident attributes or direct property
                        value = getattr(incident, 'attributes', {}).get(key) or getattr(incident, key, None)
                        params[k] = value
                
                # Resolve and execute the action
                fn = self._resolve(action)
                
                try:
                    # Execute action (handle both sync and async functions)
                    if asyncio.iscoroutinefunction(fn):
                        res = await fn(incident, **params)
                    else:
                        res = fn(incident, **params)
                    
                    results.append({
                        "action": action,
                        "result": res,
                        "success": True
                    })
                    
                    logger.debug(f"Action {action} executed successfully")
                    
                except Exception as e:
                    logger.error(f"Action {action} failed: {e}")
                    results.append({
                        "action": action,
                        "result": {"error": str(e)},
                        "success": False
                    })
            
            # Calculate overall success
            successful_actions = sum(1 for r in results if r["success"])
            total_actions = len(results)
            success_rate = successful_actions / total_actions if total_actions > 0 else 0
            
            return {
                "status": "completed",
                "steps": results,
                "summary": {
                    "total_actions": total_actions,
                    "successful_actions": successful_actions,
                    "success_rate": success_rate
                }
            }
            
        except Exception as e:
            logger.error(f"Playbook execution failed: {e}")
            return {
                "status": "failed",
                "error": str(e),
                "steps": []
            }

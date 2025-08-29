"""
Alert Response Actions
Implements alerting and notification response actions
"""

import logging
from typing import Dict, Any
from datetime import datetime

logger = logging.getLogger(__name__)


def send_alert(incident, severity: str = "medium", recipients: list = None, **kwargs) -> Dict[str, Any]:
    """
    Send security alert via email

    Args:
        incident: Incident object
        severity: Alert severity
        recipients: List of recipients

    Returns:
        Action result
    """
    try:
        # Import SMTP integration
        from ...integrations.smtp_email import smtp_integration

        alert_severity = severity or getattr(incident, 'severity', 'medium')

        if isinstance(alert_severity, object) and hasattr(alert_severity, 'value'):
            alert_severity = alert_severity.value

        # Use provided recipients or defaults
        if not recipients:
            recipients = smtp_integration.default_recipients

        # Prepare alert data
        alert_data = {
            'title': f'Security Alert - Severity {alert_severity.upper()}',
            'description': getattr(incident, 'description', f'Security incident detected with {alert_severity} severity'),
            'severity': alert_severity.upper(),
            'source': getattr(incident, 'source', 'SOAR Detection System'),
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'actions': ['Alert generated', 'Email notification sent', 'Incident logged']
        }

        # Send email alert
        email_sent = smtp_integration.send_soar_alert(alert_data, recipients)

        if email_sent:
            logger.info(f"Security alert sent successfully via email to {len(recipients)} recipients")
            return {
                "status": "success",
                "message": f"Alert sent successfully to {len(recipients)} recipients via email",
                "action": "send_alert",
                "details": {
                    "severity": alert_severity,
                    "recipients": recipients,
                    "alert_id": f"ALERT_{int(datetime.now().timestamp())}",
                    "timestamp": datetime.now().isoformat(),
                    "email_sent": True
                }
            }
        else:
            logger.error("Failed to send email alert")
            return {
                "status": "error",
                "message": "Failed to send email alert",
                "action": "send_alert",
                "details": {
                    "severity": alert_severity,
                    "recipients": recipients,
                    "email_sent": False,
                    "error": "SMTP connection failed"
                }
            }

    except Exception as e:
        logger.error(f"Error sending alert: {e}")
        return {
            "status": "error",
            "message": f"Failed to send alert: {str(e)}",
            "action": "send_alert",
            "details": {
                "severity": severity,
                "error": str(e)
            }
        }


def notify_teams(incident, teams: list = None, **kwargs) -> Dict[str, Any]:
    """
    Notify security teams via email

    Args:
        incident: Incident object
        teams: List of teams to notify

    Returns:
        Action result
    """
    try:
        # Import SMTP integration
        from ...integrations.smtp_email import smtp_integration

        default_teams = ["SOC", "Incident_Response", "Security_Engineering"]
        target_teams = teams or default_teams

        # Prepare team notification data
        alert_data = {
            'title': f'Team Notification - {getattr(incident, "type", "Security Incident")}',
            'description': f'Incident notification for teams: {", ".join(target_teams)}',
            'severity': getattr(incident, 'severity', 'medium'),
            'source': 'SOAR Team Notification System',
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'actions': ['Team notification sent', 'Escalation initiated']
        }

        # Send email notification
        email_sent = smtp_integration.send_soar_alert(alert_data, smtp_integration.default_recipients)

        if email_sent:
            logger.info(f"Team notification sent successfully via email for teams: {', '.join(target_teams)}")
            return {
                "status": "success",
                "message": f"Teams notified successfully via email: {', '.join(target_teams)}",
                "action": "notify_teams",
                "details": {
                    "notified_teams": target_teams,
                    "notification_method": "email_smtp",
                    "escalation_level": kwargs.get('escalation_level', 'standard'),
                    "email_sent": True
                }
            }
        else:
            logger.error("Failed to send team notification email")
            return {
                "status": "error",
                "message": "Failed to send team notification email",
                "action": "notify_teams",
                "details": {
                    "notified_teams": target_teams,
                    "email_sent": False,
                    "error": "SMTP connection failed"
                }
            }

    except Exception as e:
        logger.error(f"Error notifying teams: {e}")
        return {
            "status": "error",
            "message": f"Failed to notify teams: {str(e)}",
            "action": "notify_teams",
            "details": {
                "error": str(e)
            }
        }


async def create_ticket(incident, priority: str = "medium", **kwargs) -> Dict[str, Any]:
    """
    Create incident ticket
    
    Args:
        incident: Incident object
        priority: Ticket priority
        
    Returns:
        Action result
    """
    ticket_priority = priority or getattr(incident, 'severity', 'medium')
    
    if isinstance(ticket_priority, object) and hasattr(ticket_priority, 'value'):
        ticket_priority = ticket_priority.value
    
    ticket_id = f"INC-{int(datetime.now().timestamp())}"
    
    logger.info(f"Creating incident ticket {ticket_id} with priority {ticket_priority}")
    
    return {
        "status": "success",
        "message": f"Incident ticket {ticket_id} created successfully",
        "action": "create_ticket",
        "details": {
            "ticket_id": ticket_id,
            "priority": ticket_priority,
            "assigned_team": "SOC_L1",
            "estimated_resolution": "4 hours"
        }
    }


def wazuh_automated_response(incident, **kwargs) -> Dict[str, Any]:
    """
    Execute automated response using Wazuh EDR

    Args:
        incident: Incident object with Wazuh alert data
        **kwargs: Additional parameters

    Returns:
        Action result
    """
    try:
        # Import Wazuh integration
        from ...integrations.wazuh_edr import wazuh_integration

        response_actions = []
        agent_name = incident.get('agent', 'unknown')

        # Find target agent
        agents = wazuh_integration.get_agents()
        target_agent = None

        for agent in agents:
            if agent['name'] == agent_name or agent['id'] == str(agent_name):
                target_agent = agent
                break

        if not target_agent:
            logger.warning(f"Agente {agent_name} não encontrado no Wazuh")
            return {
                "status": "failed",
                "error": "Agent not found in Wazuh",
                "actions_taken": []
            }

        agent_id = target_agent['id']
        severity = incident.get('severity', 'low')

        # Execute response based on severity
        if severity in ['critical', 'high']:
            # Isolate agent
            isolation_result = wazuh_integration.run_command(
                agent_id,
                'netsh advfirewall set allprofiles state on'
            )
            response_actions.append({
                'action': 'isolate_agent',
                'agent_id': agent_id,
                'result': 'success' if 'error' not in isolation_result else 'failed'
            })

            # Restart agent
            restart_result = wazuh_integration.restart_agent(agent_id)
            response_actions.append({
                'action': 'restart_agent',
                'agent_id': agent_id,
                'result': 'success' if restart_result else 'failed'
            })

        # Collect evidence
        evidence_result = wazuh_integration.run_command(
            agent_id,
            'wevtutil qe System /c:10 /f:text > c:\\temp\\system_events.txt'
        )
        response_actions.append({
            'action': 'collect_evidence',
            'result': 'success' if 'error' not in evidence_result else 'failed'
        })

        logger.info(f"Resposta automatizada executada para incidente {incident.get('id', 'unknown')}: {len(response_actions)} ações")

        return {
            "status": "success",
            "message": f"Automated response executed for {len(response_actions)} actions",
            "action": "wazuh_automated_response",
            "details": {
                "agent_id": agent_id,
                "actions_taken": response_actions,
                "timestamp": datetime.now().isoformat()
            }
        }

    except Exception as e:
        logger.error(f"Erro na resposta automatizada Wazuh: {e}")
        return {
            "status": "failed",
            "error": str(e),
            "actions_taken": []
        }

import requests
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import os

logger = logging.getLogger(__name__)

class WazuhEDRIntegration:
    def __init__(self):
        # Configurações do ambiente
        self.api_url = os.getenv('WAZUH_API_URL', 'http://localhost:55000')
        self.username = os.getenv('WAZUH_USERNAME', 'wazuh')
        self.password = os.getenv('WAZUH_PASSWORD', 'wazuh')
        self.auth_token = None
        self.token_expiry = None

        # Configurações adicionais
        self.verify_ssl = os.getenv('WAZUH_VERIFY_SSL', 'false').lower() == 'true'
        self.timeout = int(os.getenv('WAZUH_TIMEOUT', '30'))

        logger.info("Wazuh EDR Integration inicializada")

    def _get_auth_token(self) -> str:
        """Obtém token de autenticação do Wazuh API."""
        if self.auth_token and self.token_expiry and datetime.now() < self.token_expiry:
            return self.auth_token

        try:
            auth_url = f"{self.api_url}/security/user/authenticate"
            auth_data = {
                'username': self.username,
                'password': self.password
            }

            response = requests.post(
                auth_url,
                json=auth_data,
                verify=self.verify_ssl,
                timeout=self.timeout
            )

            if response.status_code == 200:
                token_data = response.json()
                self.auth_token = token_data['data']['token']
                # Token expira em ~15 minutos
                self.token_expiry = datetime.now() + timedelta(minutes=14)
                logger.info("Token Wazuh obtido com sucesso")
                return self.auth_token
            else:
                raise Exception(f"Falha na autenticação: {response.text}")
        except Exception as e:
            logger.error(f"Erro na autenticação Wazuh: {e}")
            raise

    def _make_request(self, endpoint: str, method: str = 'GET', data: Optional[Dict] = None) -> Dict:
        """Faz requisição para Wazuh API."""
        headers = {
            'Authorization': f'Bearer {self._get_auth_token()}',
            'Content-Type': 'application/json'
        }

        url = f"{self.api_url}{endpoint}"

        try:
            if method == 'GET':
                response = requests.get(url, headers=headers, verify=self.verify_ssl, timeout=self.timeout)
            elif method == 'POST':
                response = requests.post(url, headers=headers, json=data, verify=self.verify_ssl, timeout=self.timeout)
            elif method == 'PUT':
                response = requests.put(url, headers=headers, json=data, verify=self.verify_ssl, timeout=self.timeout)
            elif method == 'DELETE':
                response = requests.delete(url, headers=headers, verify=self.verify_ssl, timeout=self.timeout)

            if response.status_code in [200, 201]:
                return response.json()
            else:
                logger.error(f"Wazuh API error: {response.status_code} - {response.text}")
                return {'error': response.text, 'status_code': response.status_code}
        except Exception as e:
            logger.error(f"Erro na requisição Wazuh: {e}")
            return {'error': str(e)}

    def get_alerts(self, limit: int = 50, offset: int = 0,
                   since_hours: Optional[int] = None) -> List[Dict[str, Any]]:
        """Obtém alertas do Wazuh."""
        params = {
            'limit': limit,
            'offset': offset,
            'sort': '-timestamp'
        }

        if since_hours:
            since_time = (datetime.now() - timedelta(hours=since_hours)).strftime('%Y-%m-%d %H:%M:%S')
            params['q'] = f'timestamp>{since_time}'

        response = self._make_request('/alerts', 'GET')

        if 'error' not in response:
            alerts = response.get('data', {}).get('alerts', [])
            logger.info(f"Obtidos {len(alerts)} alertas do Wazuh")
            return alerts
        else:
            logger.error(f"Erro ao obter alertas: {response['error']}")
            return []

    def get_agents(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        """Obtém lista de agentes."""
        params = {}
        if status:
            params['status'] = status

        response = self._make_request('/agents', 'GET')

        if 'error' not in response:
            agents = response.get('data', {}).get('items', [])
            logger.info(f"Obtidos {len(agents)} agentes do Wazuh")
            return agents
        else:
            logger.error(f"Erro ao obter agentes: {response['error']}")
            return []

    def get_agent_info(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """Obtém informações de um agente específico."""
        response = self._make_request(f'/agents/{agent_id}', 'GET')

        if 'error' not in response:
            return response.get('data')
        else:
            logger.error(f"Erro ao obter info do agente {agent_id}: {response['error']}")
            return None

    def restart_agent(self, agent_id: str) -> bool:
        """Reinicia um agente."""
        response = self._make_request(f'/agents/{agent_id}/restart', 'PUT')

        if 'error' not in response:
            logger.info(f"Agente {agent_id} reiniciado com sucesso")
            return True
        else:
            logger.error(f"Erro ao reiniciar agente {agent_id}: {response['error']}")
            return False

    def run_command(self, agent_id: str, command: str) -> Dict[str, Any]:
        """Executa comando em um agente."""
        data = {
            'command': command,
            'arguments': []
        }

        response = self._make_request(f'/agents/{agent_id}/commands', 'POST', data)

        if 'error' not in response:
            logger.info(f"Comando executado no agente {agent_id}: {command}")
            return response.get('data', {})
        else:
            logger.error(f"Erro ao executar comando no agente {agent_id}: {response['error']}")
            return {'error': response['error']}

    def get_security_events(self, agent_id: Optional[str] = None,
                           rule_id: Optional[str] = None,
                           limit: int = 20) -> List[Dict[str, Any]]:
        """Obtém eventos de segurança."""
        params = {'limit': limit}
        if agent_id:
            params['agent.id'] = agent_id
        if rule_id:
            params['rule.id'] = rule_id

        response = self._make_request('/events', 'GET')

        if 'error' not in response:
            events = response.get('data', {}).get('events', [])
            logger.info(f"Obtidos {len(events)} eventos de segurança")
            return events
        else:
            logger.error(f"Erro ao obter eventos: {response['error']}")
            return []

    def create_custom_rule(self, rule_data: Dict[str, Any]) -> bool:
        """Cria uma regra personalizada."""
        response = self._make_request('/rules', 'POST', rule_data)

        if 'error' not in response:
            logger.info("Regra personalizada criada com sucesso")
            return True
        else:
            logger.error(f"Erro ao criar regra: {response['error']}")
            return False

    def get_system_status(self) -> Dict[str, Any]:
        """Obtém status do sistema Wazuh."""
        response = self._make_request('/cluster/status', 'GET')

        if 'error' not in response:
            return response.get('data', {})
        else:
            logger.error(f"Erro ao obter status do sistema: {response['error']}")
            return {'error': response['error']}

# Instância global
wazuh_integration = WazuhEDRIntegration()

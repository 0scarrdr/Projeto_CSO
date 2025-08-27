import json
from elasticsearch import Elasticsearch
from soar.utils.logging import get_logger

logger = get_logger(__name__)

# Configuração do Elasticsearch
ELASTICSEARCH_URL = "http://elasticsearch:9200"
ES_INDEX = "soar-events"

es = Elasticsearch(ELASTICSEARCH_URL)

def send_event(event):
    try:
        res = es.index(index=ES_INDEX, document=event)
        logger.info(f"Evento enviado para Elastic SIEM: {event}")
        return {"sent": True, "event": event, "result": res}
    except Exception as e:
        logger.error(f"Erro ao enviar evento para Elastic SIEM: {e}")
        return {"sent": False, "error": str(e), "event": event}

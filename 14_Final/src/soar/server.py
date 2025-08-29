"""
Servidor principal da API SOAR
Configura e inicia o servidor FastAPI com todas as funcionalidades
"""

import uvicorn
import logging
import asyncio
from pathlib import Path
import sys

# Adicionar o diretório src ao path
sys.path.append(str(Path(__file__).parent.parent))

from api.app import app

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('soar_api.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

def main():
    """
    Função principal para iniciar o servidor SOAR API
    
    Configurações:
    - Host: 0.0.0.0 (aceita conexões de qualquer IP)
    - Port: 8000 (porta padrão)
    - Reload: True (desenvolvimento)
    - Workers: 1 (pode ser aumentado em produção)
    """
    
    logger.info("Starting SOAR API Server...")
    logger.info("API Documentation will be available at: http://localhost:8000/docs")
    logger.info("ReDoc Documentation will be available at: http://localhost:8000/redoc")
    logger.info("Health Check available at: http://localhost:8000/health")
    
    # Configuração do servidor
    config = uvicorn.Config(
        app=app,
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info",
        access_log=True,
        loop="asyncio"
    )
    
    # Iniciar servidor
    server = uvicorn.Server(config)
    
    try:
        # Executar servidor
        asyncio.run(server.serve())
        
    except KeyboardInterrupt:
        logger.info("Server shutdown requested by user")
    except Exception as e:
        logger.error(f"Server error: {e}")
        raise
    finally:
        logger.info("SOAR API Server stopped")

if __name__ == "__main__":
    main()

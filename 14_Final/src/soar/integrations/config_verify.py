import os
import hashlib
from soar.utils.logging import get_logger

logger = get_logger(__name__)

# Exemplo: verifica se arquivo de configuração está íntegro
CONFIG_REFERENCE_HASHES = {
    "/etc/ssh/sshd_config": "d41d8cd98f00b204e9800998ecf8427e",  # Exemplo
}

def verify_config(file_path):
    try:
        if not os.path.exists(file_path):
            logger.error(f"Arquivo de configuração não encontrado: {file_path}")
            return {"status": "not_found", "file": file_path}
        with open(file_path, "rb") as f:
            file_hash = hashlib.md5(f.read()).hexdigest()
        ref_hash = CONFIG_REFERENCE_HASHES.get(file_path)
        if ref_hash and file_hash == ref_hash:
            logger.info(f"Configuração verificada: {file_path} íntegra")
            return {"status": "verified", "file": file_path}
        else:
            logger.warning(f"Configuração alterada: {file_path}")
            return {"status": "changed", "file": file_path, "current_hash": file_hash, "reference_hash": ref_hash}
    except Exception as e:
        logger.error(f"Erro ao verificar configuração: {e}")
        return {"status": "error", "file": file_path, "error": str(e)}

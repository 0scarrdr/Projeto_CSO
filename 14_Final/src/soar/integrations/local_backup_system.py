"""
Local Backup System for SOAR
Sistema de backup local simples e robusto para o SOAR
"""

import os
import shutil
import zipfile
import hashlib
import json
import logging
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from pathlib import Path

logger = logging.getLogger(__name__)

class LocalBackupSystem:
    """
    Sistema de Backup Local para SOAR

    Funcionalidades:
    - Backup de diretórios específicos
    - Verificação de integridade (hash)
    - Restauração de backups
    - Limpeza automática de backups antigos
    - Logs detalhados de operações
    """

    def __init__(self, backup_dir: str = "backups", source_dirs: List[str] = None):
        """
        Inicializa o sistema de backup

        Args:
            backup_dir: Diretório onde os backups serão armazenados
            source_dirs: Lista de diretórios a serem incluídos no backup
        """
        self.backup_dir = Path(backup_dir)
        self.source_dirs = source_dirs or ["config", "src", "data", "logs"]

        # Cria diretório de backup se não existir
        self.backup_dir.mkdir(parents=True, exist_ok=True)

        # Arquivo de metadados dos backups
        self.metadata_file = self.backup_dir / "backup_metadata.json"

        logger.info(f"Sistema de backup local inicializado em: {self.backup_dir}")

    def create_backup(self, name: Optional[str] = None, description: str = "") -> Dict[str, Any]:
        """
        Cria um backup completo dos diretórios configurados

        Args:
            name: Nome personalizado do backup (opcional)
            description: Descrição do backup

        Returns:
            Dicionário com informações do backup criado
        """
        try:
            # Gera nome do backup se não fornecido
            if not name:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                name = f"backup_{timestamp}"

            backup_filename = f"{name}.zip"
            backup_path = self.backup_dir / backup_filename

            logger.info(f"Iniciando backup: {name}")

            # Cria o arquivo ZIP
            with zipfile.ZipFile(backup_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                files_added = 0
                total_size = 0

                for source_dir in self.source_dirs:
                    source_path = Path(source_dir)

                    if not source_path.exists():
                        logger.warning(f"Diretório fonte não encontrado: {source_dir}")
                        continue

                    logger.info(f"Adicionando diretório: {source_dir}")

                    # Adiciona todos os arquivos do diretório
                    for file_path in source_path.rglob('*'):
                        if file_path.is_file():
                            # Calcula caminho relativo
                            relative_path = file_path.relative_to(source_path.parent)
                            zipf.write(file_path, relative_path)

                            files_added += 1
                            total_size += file_path.stat().st_size

            # Calcula hash do arquivo para verificação de integridade
            file_hash = self._calculate_file_hash(backup_path)

            # Cria metadados do backup
            backup_info = {
                "name": name,
                "filename": backup_filename,
                "path": str(backup_path),
                "created_at": datetime.now().isoformat(),
                "description": description,
                "source_dirs": self.source_dirs.copy(),
                "files_count": files_added,
                "total_size": total_size,
                "hash": file_hash,
                "status": "completed"
            }

            # Salva metadados
            self._save_backup_metadata(backup_info)

            logger.info(f"Backup criado com sucesso: {backup_filename}")
            logger.info(f"Arquivos incluídos: {files_added}")
            logger.info(f"Tamanho total: {total_size} bytes")

            return backup_info

        except Exception as e:
            error_msg = f"Erro ao criar backup: {str(e)}"
            logger.error(error_msg)

            # Salva metadados de erro
            error_info = {
                "name": name or "unknown",
                "created_at": datetime.now().isoformat(),
                "status": "failed",
                "error": str(e)
            }
            self._save_backup_metadata(error_info)

            raise Exception(error_msg)

    def list_backups(self) -> List[Dict[str, Any]]:
        """
        Lista todos os backups disponíveis

        Returns:
            Lista de dicionários com informações dos backups
        """
        try:
            if not self.metadata_file.exists():
                return []

            with open(self.metadata_file, 'r', encoding='utf-8') as f:
                metadata = json.load(f)

            # Filtra apenas backups completados
            completed_backups = [
                backup for backup in metadata
                if backup.get('status') == 'completed'
            ]

            # Ordena por data de criação (mais recente primeiro)
            completed_backups.sort(key=lambda x: x.get('created_at', ''), reverse=True)

            return completed_backups

        except Exception as e:
            logger.error(f"Erro ao listar backups: {e}")
            return []

    def restore_backup(self, backup_name: str, restore_dir: str = "restore") -> Dict[str, Any]:
        """
        Restaura um backup específico

        Args:
            backup_name: Nome do backup a ser restaurado
            restore_dir: Diretório onde restaurar os arquivos

        Returns:
            Dicionário com informações da restauração
        """
        try:
            # Encontra o backup
            backups = self.list_backups()
            backup_info = None

            for backup in backups:
                if backup['name'] == backup_name:
                    backup_info = backup
                    break

            if not backup_info:
                raise Exception(f"Backup não encontrado: {backup_name}")

            backup_path = Path(backup_info['path'])
            if not backup_path.exists():
                raise Exception(f"Arquivo de backup não encontrado: {backup_path}")

            # Cria diretório de restauração
            restore_path = Path(restore_dir)
            restore_path.mkdir(parents=True, exist_ok=True)

            logger.info(f"Iniciando restauração: {backup_name}")

            # Extrai o backup
            with zipfile.ZipFile(backup_path, 'r') as zipf:
                zipf.extractall(restore_path)

            # Verifica integridade se hash estiver disponível
            if 'hash' in backup_info:
                calculated_hash = self._calculate_file_hash(backup_path)
                if calculated_hash != backup_info['hash']:
                    logger.warning("Hash do arquivo não corresponde - possível corrupção")

            restore_info = {
                "backup_name": backup_name,
                "restore_dir": str(restore_path),
                "restored_at": datetime.now().isoformat(),
                "files_restored": len(list(restore_path.rglob('*'))),
                "status": "completed"
            }

            logger.info(f"Restauração concluída: {backup_name}")
            return restore_info

        except Exception as e:
            error_msg = f"Erro na restauração: {str(e)}"
            logger.error(error_msg)
            return {
                "backup_name": backup_name,
                "status": "failed",
                "error": str(e)
            }

    def cleanup_old_backups(self, days_to_keep: int = 30) -> Dict[str, Any]:
        """
        Remove backups antigos

        Args:
            days_to_keep: Número de dias para manter backups

        Returns:
            Dicionário com informações da limpeza
        """
        try:
            cutoff_date = datetime.now() - timedelta(days=days_to_keep)
            removed_count = 0
            total_space_freed = 0

            # Carrega metadados
            if self.metadata_file.exists():
                with open(self.metadata_file, 'r', encoding='utf-8') as f:
                    metadata = json.load(f)
            else:
                metadata = []

            # Filtra backups a remover
            updated_metadata = []
            for backup in metadata:
                if backup.get('status') == 'completed':
                    created_at = datetime.fromisoformat(backup.get('created_at', ''))
                    if created_at < cutoff_date:
                        # Remove arquivo físico
                        backup_path = Path(backup['path'])
                        if backup_path.exists():
                            file_size = backup_path.stat().st_size
                            backup_path.unlink()
                            total_space_freed += file_size
                            removed_count += 1
                            logger.info(f"Backup removido: {backup['name']}")
                    else:
                        updated_metadata.append(backup)
                else:
                    updated_metadata.append(backup)

            # Salva metadados atualizados
            with open(self.metadata_file, 'w', encoding='utf-8') as f:
                json.dump(updated_metadata, f, indent=2, ensure_ascii=False)

            result = {
                "removed_count": removed_count,
                "space_freed": total_space_freed,
                "space_freed_mb": round(total_space_freed / (1024 * 1024), 2),
                "days_kept": days_to_keep,
                "status": "completed"
            }

            logger.info(f"Limpeza concluída: {removed_count} backups removidos")
            return result

        except Exception as e:
            error_msg = f"Erro na limpeza: {str(e)}"
            logger.error(error_msg)
            return {
                "status": "failed",
                "error": str(e)
            }

    def get_backup_info(self, backup_name: str) -> Optional[Dict[str, Any]]:
        """
        Obtém informações detalhadas de um backup específico

        Args:
            backup_name: Nome do backup

        Returns:
            Dicionário com informações do backup ou None se não encontrado
        """
        backups = self.list_backups()
        for backup in backups:
            if backup['name'] == backup_name:
                return backup
        return None

    def verify_backup_integrity(self, backup_name: str) -> Dict[str, Any]:
        """
        Verifica a integridade de um backup

        Args:
            backup_name: Nome do backup a verificar

        Returns:
            Dicionário com resultado da verificação
        """
        try:
            backup_info = self.get_backup_info(backup_name)
            if not backup_info:
                return {"status": "not_found", "backup_name": backup_name}

            backup_path = Path(backup_info['path'])
            if not backup_path.exists():
                return {
                    "status": "file_missing",
                    "backup_name": backup_name,
                    "expected_path": str(backup_path)
                }

            # Verifica hash se disponível
            if 'hash' in backup_info:
                calculated_hash = self._calculate_file_hash(backup_path)
                hash_match = calculated_hash == backup_info['hash']
            else:
                hash_match = None

            # Verifica se arquivo ZIP é válido
            try:
                with zipfile.ZipFile(backup_path, 'r') as zipf:
                    zipf.testzip()
                zip_valid = True
            except Exception:
                zip_valid = False

            result = {
                "backup_name": backup_name,
                "file_exists": True,
                "file_size": backup_path.stat().st_size,
                "hash_verified": hash_match,
                "zip_integrity": zip_valid,
                "status": "valid" if (hash_match in [True, None] and zip_valid) else "corrupted"
            }

            return result

        except Exception as e:
            return {
                "backup_name": backup_name,
                "status": "error",
                "error": str(e)
            }

    def _calculate_file_hash(self, file_path: Path) -> str:
        """Calcula hash SHA256 de um arquivo"""
        hash_sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()

    def _save_backup_metadata(self, backup_info: Dict[str, Any]):
        """Salva metadados do backup"""
        try:
            # Carrega metadados existentes
            if self.metadata_file.exists():
                with open(self.metadata_file, 'r', encoding='utf-8') as f:
                    metadata = json.load(f)
            else:
                metadata = []

            # Adiciona novo backup
            metadata.append(backup_info)

            # Salva metadados atualizados
            with open(self.metadata_file, 'w', encoding='utf-8') as f:
                json.dump(metadata, f, indent=2, ensure_ascii=False)

        except Exception as e:
            logger.error(f"Erro ao salvar metadados: {e}")

# Instância global do sistema de backup
backup_system = LocalBackupSystem()

# Funções de conveniência para uso direto
def create_backup(name: Optional[str] = None, description: str = "") -> Dict[str, Any]:
    """Função de conveniência para criar backup"""
    return backup_system.create_backup(name, description)

def list_backups() -> List[Dict[str, Any]]:
    """Função de conveniência para listar backups"""
    return backup_system.list_backups()

def restore_backup(backup_name: str, restore_dir: str = "restore") -> Dict[str, Any]:
    """Função de conveniência para restaurar backup"""
    return backup_system.restore_backup(backup_name, restore_dir)

def cleanup_backups(days_to_keep: int = 30) -> Dict[str, Any]:
    """Função de conveniência para limpar backups antigos"""
    return backup_system.cleanup_old_backups(days_to_keep)

if __name__ == "__main__":
    # Exemplo de uso
    print("🧪 Testando sistema de backup local...")

    # Cria backup
    result = create_backup("teste_backup", "Backup de teste do sistema")
    print(f"✅ Backup criado: {result['name']}")

    # Lista backups
    backups = list_backups()
    print(f"📋 Backups disponíveis: {len(backups)}")

    # Verifica integridade
    if backups:
        verify_result = backup_system.verify_backup_integrity(backups[0]['name'])
        print(f"🔍 Verificação: {verify_result['status']}")

    print("✅ Sistema de backup local funcionando!")

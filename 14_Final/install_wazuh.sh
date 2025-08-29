#!/bin/bash
# Script de Instalação Automática do Wazuh Manager
# Execute como root: sudo bash install_wazuh.sh

set -e

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Função para log
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}"
}

warning() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

info() {
    echo -e "${BLUE}[INFO] $1${NC}"
}

# Verificar se está executando como root
if [[ $EUID -ne 0 ]]; then
   error "Este script deve ser executado como root"
   exit 1
fi

log "🚀 Iniciando instalação do Wazuh Manager..."

# Atualizar sistema
log "📦 Atualizando sistema..."
apt update && apt upgrade -y

# Instalar dependências
log "📦 Instalando dependências..."
apt install -y curl apt-transport-https lsb-release gnupg2

# Adicionar repositório Wazuh
log "📦 Adicionando repositório Wazuh..."
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list

# Atualizar lista de pacotes
log "📦 Atualizando lista de pacotes..."
apt update

# Instalar Wazuh Manager
log "📦 Instalando Wazuh Manager..."
apt install -y wazuh-manager

# Instalar Wazuh API
log "📦 Instalizando Wazuh API..."
apt install -y wazuh-api

# Instalar Filebeat (para integração com Elasticsearch)
log "📦 Instalando Filebeat..."
apt install -y filebeat

# Configurar Wazuh API
log "⚙️ Configurando Wazuh API..."
API_CONFIG="/var/ossec/api/configuration/api.yaml"

if [ -f "$API_CONFIG" ]; then
    # Backup do arquivo original
    cp "$API_CONFIG" "$API_CONFIG.backup"

    # Configurar API para aceitar conexões
    cat > "$API_CONFIG" << EOF
host: "0.0.0.0"
port: "55000"
https: "no"
basic_auth: "yes"
BehindProxyServer: "no"
cors:
  enabled: "yes"
  source_route: "*"
  expose_headers: "*"
  allow_headers: "*"
  allow_credentials: "no"
cache:
  enabled: "yes"
  time: "0.750"
access:
  max_login_attempts: 5
  block_time: 300
  max_request_per_minute: 300
EOF

    log "✅ Wazuh API configurado"
else
    warning "Arquivo de configuração da API não encontrado: $API_CONFIG"
fi

# Iniciar serviços
log "🚀 Iniciando serviços Wazuh..."
systemctl daemon-reload
systemctl enable wazuh-manager
systemctl enable wazuh-api
systemctl start wazuh-manager
systemctl start wazuh-api

# Verificar status dos serviços
log "🔍 Verificando status dos serviços..."
if systemctl is-active --quiet wazuh-manager; then
    log "✅ Wazuh Manager está rodando"
else
    error "❌ Wazuh Manager não está rodando"
fi

if systemctl is-active --quiet wazuh-api; then
    log "✅ Wazuh API está rodando"
else
    error "❌ Wazuh API não está rodando"
fi

# Configurar firewall
log "🔥 Configurando firewall..."
ufw allow 55000/tcp
ufw allow 1514/tcp
ufw allow 1515/tcp
ufw --force enable

# Criar usuário para API (opcional)
log "👤 Criando usuário para API..."
/var/ossec/api/scripts/wazuh-api user add wazuh wazuh -f

# Mostrar informações de acesso
log "📋 Informações de acesso:"
echo ""
echo "=========================================="
echo "🎉 WAZUH MANAGER INSTALADO COM SUCESSO!"
echo "=========================================="
echo ""
echo "📍 URLs de Acesso:"
echo "   • Wazuh API: http://$(hostname -I | awk '{print $1}'):55000"
echo "   • Wazuh Manager: $(hostname -I | awk '{print $1}')"
echo ""
echo "👤 Credenciais padrão:"
echo "   • Usuário: wazuh"
echo "   • Senha: wazuh"
echo ""
echo "🔧 Portas abertas:"
echo "   • 55000/tcp - Wazuh API"
echo "   • 1514/tcp  - Agente comunicação"
echo "   • 1515/tcp  - Agente registro"
echo ""
echo "📁 Arquivos de log:"
echo "   • /var/ossec/logs/alerts/alerts.log"
echo "   • /var/ossec/logs/api.log"
echo ""
echo "=========================================="
echo "📖 PRÓXIMOS PASSOS:"
echo "=========================================="
echo "1. Configure o .env do seu projeto SOAR:"
echo "   WAZUH_API_URL=http://$(hostname -I | awk '{print $1}'):55000"
echo "   WAZUH_USERNAME=wazuh"
echo "   WAZUH_PASSWORD=wazuh"
echo ""
echo "2. Teste a integração:"
echo "   python test_wazuh_integration.py"
echo ""
echo "3. Instale agentes nos endpoints:"
echo "   https://documentation.wazuh.com/current/installation-guide/wazuh-agent/index.html"
echo ""
echo "=========================================="

log "✅ Instalação do Wazuh Manager concluída com sucesso!"

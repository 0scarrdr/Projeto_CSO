#!/bin/bash
# Script para instalar agentes Wazuh
# Execute como root: sudo bash install_wazuh_agent.sh

set -e

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Função para log
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}"
}

info() {
    echo -e "${BLUE}[INFO] $1${NC}"
}

# Verificar se está executando como root
if [[ $EUID -ne 0 ]]; then
   error "Este script deve ser executado como root"
   exit 1
fi

# Detectar sistema operacional
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    VERSION=$VERSION_ID
else
    error "Sistema operacional não suportado"
    exit 1
fi

# Solicitar IP do Wazuh Manager
read -p "Digite o IP do Wazuh Manager: " WAZUH_MANAGER_IP

if [ -z "$WAZUH_MANAGER_IP" ]; then
    error "IP do Wazuh Manager é obrigatório"
    exit 1
fi

log "🚀 Iniciando instalação do Wazuh Agent..."
log "📍 Sistema detectado: $OS $VERSION"
log "🎯 Wazuh Manager: $WAZUH_MANAGER_IP"

# Instalar Wazuh Agent baseado no SO
case $OS in
    ubuntu|debian)
        log "📦 Instalando para Ubuntu/Debian..."

        # Adicionar repositório
        curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
        echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list

        # Atualizar e instalar
        apt update
        apt install -y wazuh-agent

        # Configurar manager
        sed -i "s/MANAGER_IP/$WAZUH_MANAGER_IP/" /var/ossec/etc/ossec.conf
        ;;

    centos|rhel|fedora)
        log "📦 Instalando para CentOS/RHEL/Fedora..."

        # Adicionar repositório
        cat > /etc/yum.repos.d/wazuh.repo << EOF
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-\$releasever - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
EOF

        # Instalar
        yum install -y wazuh-agent

        # Configurar manager
        sed -i "s/MANAGER_IP/$WAZUH_MANAGER_IP/" /var/ossec/etc/ossec.conf
        ;;

    *)
        error "Sistema operacional não suportado: $OS"
        echo "Sistemas suportados: Ubuntu, Debian, CentOS, RHEL, Fedora"
        exit 1
        ;;
esac

# Configurar Wazuh Manager no arquivo de configuração
log "⚙️ Configurando Wazuh Manager..."
OSSEC_CONF="/var/ossec/etc/ossec.conf"

if [ -f "$OSSEC_CONF" ]; then
    # Fazer backup
    cp "$OSSEC_CONF" "$OSSEC_CONF.backup"

    # Substituir IP do manager
    sed -i "s/<server-ip>.*<\/server-ip>/<server-ip>$WAZUH_MANAGER_IP<\/server-ip>/g" "$OSSEC_CONF"

    log "✅ Configuração do manager atualizada"
else
    error "Arquivo de configuração não encontrado: $OSSEC_CONF"
fi

# Iniciar serviço
log "🚀 Iniciando Wazuh Agent..."
systemctl daemon-reload
systemctl enable wazuh-agent
systemctl start wazuh-agent

# Verificar status
if systemctl is-active --quiet wazuh-agent; then
    log "✅ Wazuh Agent está rodando"
else
    error "❌ Wazuh Agent não está rodando"
    exit 1
fi

# Registrar agente no manager
log "📝 Registrando agente no manager..."
/var/ossec/bin/agent-auth -m $WAZUH_MANAGER_IP -A $(hostname)

# Reiniciar agente
systemctl restart wazuh-agent

# Mostrar informações
log "📋 Informações do agente:"
echo ""
echo "=========================================="
echo "🎉 WAZUH AGENT INSTALADO COM SUCESSO!"
echo "=========================================="
echo ""
echo "📍 Informações:"
echo "   • Manager IP: $WAZUH_MANAGER_IP"
echo "   • Agent Name: $(hostname)"
echo "   • Status: $(systemctl is-active wazuh-agent)"
echo ""
echo "📁 Arquivos importantes:"
echo "   • Config: /var/ossec/etc/ossec.conf"
echo "   • Logs: /var/ossec/logs/ossec.log"
echo "   • PID: /var/ossec/var/run/wazuh-agentd.pid"
echo ""
echo "🔧 Comandos úteis:"
echo "   • Status: systemctl status wazuh-agent"
echo "   • Logs: tail -f /var/ossec/logs/ossec.log"
echo "   • Restart: systemctl restart wazuh-agent"
echo ""
echo "=========================================="

log "✅ Instalação do Wazuh Agent concluída com sucesso!"

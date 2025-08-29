#!/bin/bash
# Script para configurar integração Wazuh no projeto SOAR
# Execute no diretório do projeto SOAR

set -e

# Cores
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

info() {
    echo -e "${BLUE}[INFO] $1${NC}"
}

warning() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

# Verificar se estamos no diretório correto
if [ ! -f ".env" ]; then
    echo "❌ Arquivo .env não encontrado!"
    echo "Execute este script no diretório raiz do projeto SOAR"
    exit 1
fi

log "🔧 Configurando integração Wazuh no SOAR..."

# Solicitar informações do Wazuh
read -p "Digite o IP do Wazuh Manager: " WAZUH_IP
read -p "Digite a porta da API (padrão: 55000): " WAZUH_PORT
read -p "Digite o usuário da API (padrão: wazuh): " WAZUH_USER
read -s -p "Digite a senha da API (padrão: wazuh): " WAZUH_PASS
echo ""

# Usar valores padrão se não informados
WAZUH_PORT=${WAZUH_PORT:-55000}
WAZUH_USER=${WAZUH_USER:-wazuh}
WAZUH_PASS=${WAZUH_PASS:-wazuh}

# Verificar se as configurações já existem
if grep -q "WAZUH_API_URL" .env; then
    warning "Configurações Wazuh já existem no .env"
    read -p "Deseja sobrescrever? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log "✅ Configuração mantida"
        exit 0
    fi
fi

# Fazer backup do .env
cp .env .env.backup.$(date +%Y%m%d_%H%M%S)
log "📋 Backup do .env criado"

# Adicionar configurações Wazuh
cat >> .env << EOF

# Wazuh EDR Configuration
WAZUH_API_URL=http://$WAZUH_IP:$WAZUH_PORT
WAZUH_USERNAME=$WAZUH_USER
WAZUH_PASSWORD=$WAZUH_PASS
WAZUH_VERIFY_SSL=false
WAZUH_TIMEOUT=30
WAZUH_AUTO_SCAN_INTERVAL=300
WAZUH_CRITICAL_SEVERITY_THRESHOLD=12
EOF

log "✅ Configurações Wazuh adicionadas ao .env"

# Testar conexão (opcional)
read -p "Deseja testar a conexão com o Wazuh? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    log "🧪 Testando conexão..."

    if command -v python3 &> /dev/null; then
        python3 -c "
import requests
import sys

try:
    # Testar autenticação
    auth_url = f'http://$WAZUH_IP:$WAZUH_PORT/security/user/authenticate'
    response = requests.post(auth_url, json={'username': '$WAZUH_USER', 'password': '$WAZUH_PASS'}, timeout=10)

    if response.status_code == 200:
        print('✅ Conexão com Wazuh estabelecida com sucesso!')
        print('✅ Credenciais válidas')
    else:
        print(f'❌ Erro na autenticação: {response.status_code}')
        sys.exit(1)

except Exception as e:
    print(f'❌ Erro de conexão: {e}')
    sys.exit(1)
"
    else
        warning "Python3 não encontrado, pulando teste de conexão"
    fi
fi

# Mostrar informações
echo ""
echo "=========================================="
echo "🎉 WAZUH INTEGRADO COM SUCESSO!"
echo "=========================================="
echo ""
echo "📍 Configurações aplicadas:"
echo "   • API URL: http://$WAZUH_IP:$WAZUH_PORT"
echo "   • Usuário: $WAZUH_USER"
echo "   • Timeout: 30s"
echo "   • SSL Verify: false"
echo ""
echo "🔧 Próximos passos:"
echo "   1. Teste a integração: python test_wazuh_integration.py"
echo "   2. Instale agentes nos endpoints"
echo "   3. Configure alertas no Wazuh Manager"
echo ""
echo "📁 Arquivos criados/modificados:"
echo "   • .env (configurações adicionadas)"
echo "   • .env.backup.* (backup)"
echo ""
echo "=========================================="

log "✅ Configuração da integração Wazuh concluída!"

# 🐳 SOAR Docker Deployment

Sistema completo de **Security Orchestration, Automation and Response (SOAR)** containerizado com Docker.

## 📋 Pré-requisitos

- **Docker** >= 20.10
- **Docker Compose** >= 1.29
- **4GB RAM** mínimo (8GB recomendado)
- **20GB** de espaço em disco

## 🚀 Quick Start

### Windows (PowerShell)
```powershell
# Verificar pré-requisitos
.\deploy.ps1 check

# Iniciar sistema completo
.\deploy.ps1 start

# Testar funcionamento
.\deploy.ps1 test
```

### Linux/macOS (Bash)
```bash
# Dar permissão de execução
chmod +x deploy.sh

# Verificar pré-requisitos
./deploy.sh check

# Iniciar sistema completo
./deploy.sh start

# Testar funcionamento
./deploy.sh test
```

## 🏗️ Arquitetura do Sistema

### Serviços Incluídos

| Serviço | Porta | Descrição |
|---------|-------|-----------|
| **SOAR API** | 8000 | API REST principal do sistema |
| **Elasticsearch** | 9200 | Armazenamento de eventos e logs |
| **Kibana** | 5601 | Visualização de dados ELK |
| **Prometheus** | 9090 | Coleta de métricas |
| **Grafana** | 3000 | Dashboards e visualizações |
| **Redis** | 6379 | Cache e filas |
| **Nginx** | 80/443 | Proxy reverso (prod) |

### URLs de Acesso

- 🌐 **SOAR API**: http://localhost:8000
- 📚 **Documentação**: http://localhost:8000/docs
- 📊 **Grafana**: http://localhost:3000 (admin/admin)
- 🔍 **Kibana**: http://localhost:5601
- 📈 **Prometheus**: http://localhost:9090
- ✅ **Health Check**: http://localhost:8000/health

## 🛠️ Comandos Disponíveis

### Gerenciamento Básico
```bash
# Iniciar ambiente de desenvolvimento
./deploy.sh start

# Iniciar ambiente de produção
./deploy.sh start-prod

# Parar serviços
./deploy.sh stop

# Reiniciar serviços
./deploy.sh restart

# Ver status dos containers
./deploy.sh status

# Ver logs em tempo real
./deploy.sh logs
```

### Manutenção
```bash
# Verificar saúde dos serviços
./deploy.sh health

# Executar testes de funcionalidade
./deploy.sh test

# Fazer backup dos dados
./deploy.sh backup

# Limpar containers antigos
./deploy.sh cleanup

# Rebuild das imagens
./deploy.sh build
```

## 🔧 Configuração

### Variáveis de Ambiente

O sistema suporta as seguintes variáveis de ambiente:

```env
# Configuração da API
ENVIRONMENT=development|production
LOG_LEVEL=DEBUG|INFO|WARNING|ERROR

# Integração com serviços
ELASTICSEARCH_URL=http://elasticsearch:9200
REDIS_URL=redis://redis:6379
PROMETHEUS_GATEWAY=http://prometheus:9090

# Configuração de performance
WORKERS=4
MAX_REQUESTS=1000
TIMEOUT=60
```

### Personalização

Para personalizar a configuração, edite os arquivos:
- `docker-compose.yml` - Ambiente de desenvolvimento
- `docker-compose.prod.yml` - Ambiente de produção
- `prometheus.yml` - Configuração do Prometheus
- `nginx.conf` - Configuração do proxy reverso

## 📊 Monitoramento

### Métricas Prometheus

O sistema expõe métricas no formato Prometheus em `/metrics`:

```bash
# Acessar métricas diretamente
curl http://localhost:8000/metrics

# Ver métricas no Prometheus
open http://localhost:9090
```

### Dashboards Grafana

Dashboards pré-configurados incluem:
- **SOAR Overview** - Visão geral do sistema
- **Performance Metrics** - KPIs e tempos de resposta
- **Security Events** - Eventos de segurança
- **Integration Status** - Status das integrações

### KPIs Monitorados

Conforme especificado no enunciado:
- ⏱️ Time to detect < 1 minute
- 🚨 Time to respond < 5 minutes
- 🎯 False positive rate < 0.1%
- 🛡️ Successful containment > 95%
- 🔄 Recovery accuracy > 99%
- 📁 Evidence preservation = 100%
- 🎯 Classification accuracy > 95%
- 📊 Risk assessment accuracy > 90%
- 🔮 Prediction accuracy > 85%
- 🔍 Pattern recognition rate > 90%

## 🧪 Testes

### Testes Automáticos
```bash
# Executar suite de testes completa
./deploy.sh test

# Verificar apenas health checks
./deploy.sh health
```

### Testes Manuais

#### 1. Enviar Evento de Segurança
```bash
curl -X POST http://localhost:8000/events \
  -H "Authorization: Bearer demo-token" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "malware",
    "severity": "high",
    "source_ip": "192.168.1.100",
    "description": "Malware detection test"
  }'
```

#### 2. Verificar KPIs
```bash
curl -H "Authorization: Bearer demo-token" \
  http://localhost:8000/metrics/kpis
```

#### 3. Executar Ação de Integração
```bash
curl -X POST http://localhost:8000/integrations/actions \
  -H "Authorization: Bearer demo-token" \
  -H "Content-Type: application/json" \
  -d '{
    "action_type": "isolate",
    "target": "192.168.1.100",
    "priority": "high"
  }'
```

## 🔒 Segurança

### Autenticação
- Todos os endpoints protegidos requerem Bearer token
- Token padrão para desenvolvimento: `demo-token`
- Em produção, configurar JWT com chaves seguras

### Network Security
- Containers isolados em rede Docker
- Nginx com rate limiting configurado
- Headers de segurança aplicados

### Data Protection
- Dados persistidos em volumes Docker
- Backup automático configurável
- Logs com rotação automática

## 🚀 Deploy em Produção

### 1. Configuração de Produção
```bash
# Usar compose de produção
./deploy.sh start-prod
```

### 2. Configurações Recomendadas
- **CPU**: 4+ cores
- **RAM**: 8GB+ 
- **Storage**: SSD com 50GB+
- **Network**: Latência baixa

### 3. Monitoramento Adicional
- Configurar alertas no Grafana
- Integrar com sistemas de logging centralizados
- Configurar backup automático

## 🐛 Troubleshooting

### Problemas Comuns

#### 1. Containers não iniciam
```bash
# Verificar logs
./deploy.sh logs

# Verificar recursos do sistema
docker system df
docker stats
```

#### 2. API não responde
```bash
# Verificar saúde da API
curl http://localhost:8000/health

# Verificar logs específicos
docker logs soar
```

#### 3. Elasticsearch não conecta
```bash
# Verificar status do cluster
curl http://localhost:9200/_cluster/health

# Reiniciar Elasticsearch
docker restart elasticsearch
```

#### 4. Memória insuficiente
```bash
# Verificar uso de memória
docker stats

# Aumentar limites no docker-compose.yml
# Fechar aplicações desnecessárias
```

### Logs e Debugging

```bash
# Logs de todos os serviços
./deploy.sh logs

# Logs de serviço específico
docker logs -f soar
docker logs -f elasticsearch
docker logs -f prometheus

# Entrar no container para debug
docker exec -it soar bash
```

## 📝 Backup e Restore

### Backup Automático
```bash
# Fazer backup completo
./deploy.sh backup

# Backups são salvos em ./backups/
```

### Restore Manual
```bash
# Parar serviços
./deploy.sh stop

# Restaurar dados Redis
docker cp backup/redis-dump.rdb redis:/data/dump.rdb

# Reiniciar serviços
./deploy.sh start
```

## 🤝 Suporte

Para suporte e issues:
1. Verificar logs com `./deploy.sh logs`
2. Executar health check com `./deploy.sh health`
3. Consultar documentação da API em http://localhost:8000/docs
4. Verificar recursos do sistema disponíveis

---

## 📈 Performance Tuning

### Para Ambientes de Alta Carga

1. **Ajustar Workers**:
```yaml
environment:
  - WORKERS=8
  - MAX_REQUESTS=2000
```

2. **Aumentar Recursos**:
```yaml
deploy:
  resources:
    limits:
      cpus: '4.0'
      memory: 4G
```

3. **Configurar Load Balancing**:
```yaml
# Adicionar múltiplas instâncias da API
```

🎯 **Sistema SOAR pronto para produção com monitoramento completo!**

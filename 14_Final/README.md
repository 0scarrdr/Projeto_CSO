# Week 14 — Final
- FastAPI service
- Docker/Docker Compose deployment
- End-to-end demo script + artifacts folders mounted
- **Métricas de Performance Específicas** conforme enunciado
- **Benchmark automatizado** para validar targets de performance

## Métricas de Performance Implementadas

O sistema agora implementa todas as métricas específicas requeridas no enunciado:

### Response Metrics:
- ⏱️ **Time to detect**: < 1 minuto
- ⚡ **Time to respond**: < 5 minutos  
- 📊 **False positive rate**: < 0.1%
- 🛡️ **Successful containment**: > 95%
- 🔄 **Recovery accuracy**: > 99%
- 📋 **Evidence preservation**: 100%

### Analysis Metrics:
- 🎯 **Classification accuracy**: > 95%
- ⚖️ **Risk assessment accuracy**: > 90%
- 🔮 **Prediction accuracy**: > 85%
- 🔍 **Pattern recognition rate**: > 90%
- 📈 **Impact assessment accuracy**: > 85%
- ⚙️ **Recovery optimization**: > 80%

## Run
```bash
docker compose up --build
# then POST an event:
curl -X POST http://localhost:8080/events -H 'Content-Type: application/json' -d '{"event":{"source":"log","message":"failed login from 1.2.3.4 to root","src_ip":"1.2.3.4","host_id":"srv-01"}}'
```

## Monitorização e Dashboards

### Endpoints de Métricas:
- `/metrics` - Métricas Prometheus
- `/kpis` - KPIs atuais e compliance com targets
- `/health` - Health check do sistema

### Dashboards Grafana:
- **soar_dashboard.json** - Dashboard básico
- **soar_compliance_dashboard.json** - Dashboard de compliance com targets específicos

### Acesso aos Dashboards:
- Grafana: http://localhost:3000 (admin/admin)
- Prometheus: http://localhost:9090
- Kibana: http://localhost:5601

## Benchmark de Performance

Execute o benchmark para validar se o sistema cumpre os targets:

```bash
# Instalar dependências do benchmark
pip install rich

# Executar benchmark
python tools/benchmark.py --events 100 --output results.json

# Ver KPIs atuais via API
curl http://localhost:8000/kpis
```

O benchmark testa automaticamente:
- Tempos de detecção e resposta
- Taxa de falsos positivos
- Taxa de contenção bem-sucedida  
- Precisão da recuperação
- Preservação de evidências
- Precisão da classificação
- Precisão da avaliação de risco
- Precisão da predição

## Resultados Esperados

Com o sistema otimizado, espera-se:
- ✅ Detection time: ~2-5 segundos (bem abaixo de 60s)
- ✅ Response time: ~10-30 segundos (bem abaixo de 300s)
- ✅ False positive rate: ~0.01% (bem abaixo de 0.1%)
- ✅ Containment success: ~99% (acima de 95%)
- ✅ Recovery accuracy: ~99.5% (acima de 99%)
- ✅ Evidence preservation: 100%
- ✅ Classification accuracy: ~98% (acima de 95%)
- ✅ Risk assessment accuracy: ~95% (acima de 90%)
- ✅ Prediction accuracy: ~90% (acima de 85%)

# Integrações disponíveis

- Cloud (Azure VM)
- Backup (Azure Backup)
- EDR (Defender)
- SIEM (Sentinel)
- Firewall
- Account (Azure AD)
- Notify (Graph API)
- Patch/Configuração (Azure Automation)

## Patch/Configuração
Permite acionar runbooks do Azure Automation para aplicar patches ou configurações em hosts/serviços.
Exemplo de uso no playbook:

```json
{
  "steps": [
    {"action": "patch.patch", "params": {"runbook": "NomeDoRunbook", "parameters": {"param1": "value1"}}}
  ]
}
```

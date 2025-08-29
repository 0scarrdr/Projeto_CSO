# SOAR Test Suite

Este diretório contém a suíte completa de testes para o sistema SOAR (Security Orchestration, Automation and Response).

## 📋 Visão Geral dos Testes

### Estrutura dos Testes

```
tests/
├── test_core.py          # Testes unitários do núcleo do sistema
├── test_detection.py     # Testes do componente de detecção
├── test_analysis.py      # Testes do componente de análise
├── test_response.py      # Testes do componente de resposta
├── test_prediction.py    # Testes do componente de predição
├── test_integration.py   # Testes de integração end-to-end
├── test_api.py          # Testes da API REST
├── run_tests.py         # Executor principal de testes
├── load_test.py         # Testes de carga e performance
└── README.md           # Esta documentação
```

## 🚀 Como Executar os Testes

### Pré-requisitos

1. **Python 3.8+** instalado
2. **Dependências instaladas**:
   ```bash
   pip install pytest pytest-asyncio pytest-cov rich aiohttp fastapi
   ```

3. **SOAR API em execução** (para testes de API e integração):
   ```bash
   cd src/soar
   python server.py
   ```

### Execução Básica

#### Executar Todos os Testes
```bash
# Do diretório raiz do projeto
python tests/run_tests.py
```

#### Executar Testes Unitários Apenas
```bash
python tests/run_tests.py --unit
```

#### Executar Testes de Integração
```bash
python tests/run_tests.py --integration
```

#### Executar Testes de API
```bash
python tests/run_tests.py --api
```

#### Executar Testes de Performance
```bash
python tests/run_tests.py --performance
```

#### Executar Smoke Tests (Rápidos)
```bash
python tests/run_tests.py --smoke
```

### Usando Pytest Diretamente

#### Executar Testes Específicos
```bash
# Testes de um componente específico
pytest tests/test_core.py -v

# Testes de uma classe específica
pytest tests/test_detection.py::TestThreatDetector -v

# Testes de um método específico
pytest tests/test_core.py::TestIncidentHandler::test_handle_incident_success -v
```

#### Com Cobertura de Código
```bash
pytest --cov=src/soar --cov-report=html
```

#### Com Relatório Detalhado
```bash
pytest -v --tb=long --durations=10
```

## 📊 Tipos de Testes

### 1. Testes Unitários (`test_*.py`)
- **Propósito**: Testar componentes individuais isoladamente
- **Cobertura**:
  - `test_core.py`: IncidentHandler e componentes principais
  - `test_detection.py`: ThreatDetector e classificação
  - `test_analysis.py`: IncidentAnalyzer e avaliação de risco
  - `test_response.py`: AutomatedResponder e playbooks
  - `test_prediction.py`: ThreatPredictor e forecasting

### 2. Testes de Integração (`test_integration.py`)
- **Propósito**: Testar interação entre componentes
- **Cenários**:
  - Processamento completo de incidentes
  - Fluxo detecção → análise → resposta → predição
  - Cenários de ataque complexos
  - Tratamento de erros e recuperação

### 3. Testes de API (`test_api.py`)
- **Propósito**: Testar endpoints REST da API
- **Cobertura**:
  - Endpoints básicos (`/`, `/health`, `/status`)
  - Processamento de incidentes (`POST /incidents`)
  - Métricas e KPIs
  - Validação de dados e tratamento de erros

### 4. Testes de Performance
- **Load Testing** (`load_test.py`): Testa performance sob carga
- **Benchmarking**: Valida targets de performance do enunciado

## 🎯 Targets de Performance

Os testes validam os seguintes targets especificados no enunciado:

### Response Metrics
- ✅ **Time to detect**: < 1 minuto
- ✅ **Time to respond**: < 5 minutos
- ✅ **False positive rate**: < 0.1%
- ✅ **Successful containment**: > 95%
- ✅ **Recovery accuracy**: > 99%
- ✅ **Evidence preservation**: 100%

### Analysis Metrics
- ✅ **Classification accuracy**: > 95%
- ✅ **Risk assessment accuracy**: > 90%
- ✅ **Prediction accuracy**: > 85%
- ✅ **Pattern recognition rate**: > 90%
- ✅ **Impact assessment accuracy**: > 85%
- ✅ **Recovery optimization**: > 80%

## 📈 Relatórios e Resultados

### Relatório de Testes
Após execução, é gerado automaticamente:
- **Arquivo**: `test_results.json`
- **Conteúdo**: Resultados detalhados, métricas, tempos de execução

### Cobertura de Código
```bash
pytest --cov=src/soar --cov-report=html
```
Gera relatório HTML em `htmlcov/index.html`

### Testes de Carga
```bash
python tests/load_test.py --requests 1000 --concurrency 50
```

## 🔧 Configuração dos Testes

### Arquivo `pytest.ini`
Configurações globais do pytest:
- Paths de teste
- Marcadores personalizados
- Relatórios de cobertura
- Configurações asyncio

### Fixtures Comuns
- `sample_event`: Evento de segurança de exemplo
- `sample_incident`: Incidente processado de exemplo
- `mock_incident_handler`: Mock do handler principal

## 🚨 Tratamento de Erros

### Testes que Falham
- **Verificar dependências**: Todos os imports devem funcionar
- **API não executando**: Para testes de API, iniciar servidor primeiro
- **Timeouts**: Ajustar timeouts em `pytest.ini` se necessário

### Debugging
```bash
# Executar com debug detalhado
pytest -v -s --tb=long

# Parar no primeiro erro
pytest --maxfail=1

# Executar testes específicos que falharam
pytest --lf
```

## 📝 Adicionando Novos Testes

### Estrutura de Teste Unitário
```python
import pytest
from soar.component import ComponentClass

class TestComponentClass:
    def test_method_name(self):
        # Arrange
        component = ComponentClass()

        # Act
        result = component.method_name()

        # Assert
        assert result == expected_value
```

### Testes Assíncronos
```python
@pytest.mark.asyncio
async def test_async_method(self):
    # Para métodos async
    result = await component.async_method()
    assert result.success
```

### Testes de Integração
```python
@pytest.mark.integration
def test_component_integration(self):
    # Testar interação entre componentes
    detector = ThreatDetector()
    analyzer = IncidentAnalyzer()

    incident = detector.classify(event)
    analysis = analyzer.analyze(incident)

    assert analysis.risk_score > 0
```

## 🎉 Boas Práticas

1. **Isolamento**: Cada teste deve ser independente
2. **Nomenclatura**: `test_*` para funções, `Test*` para classes
3. **Fixtures**: Usar fixtures para setup/teardown comum
4. **Marcadores**: Usar marcadores para categorizar testes
5. **Asserções**: Ser específico nas asserções
6. **Cobertura**: Manter cobertura > 80%

## 📞 Suporte

Para dúvidas sobre os testes:
1. Verificar logs detalhados com `-v`
2. Usar `--tb=long` para tracebacks completos
3. Consultar `test_results.json` para análise de falhas
4. Verificar cobertura com `--cov-report=html`

# Multi-stage build para otimização
FROM python:3.11-slim as builder

# Instalar dependências de build
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copiar e instalar dependências
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Imagem final
FROM python:3.11-slim

# Copiar dependências instaladas
COPY --from=builder /root/.local /root/.local

# Configurar diretório de trabalho
WORKDIR /app

# Copiar código da aplicação
COPY src/ ./src/
COPY *.yml ./

# Configurar Python path
ENV PYTHONPATH=/app/src
ENV PATH=/root/.local/bin:$PATH

# Expor porta
EXPOSE 8000

# Comando de inicialização
CMD ["python", "-m", "uvicorn", "soar.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
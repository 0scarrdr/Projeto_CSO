# Imagem base leve
FROM python:3.11-slim

# Evita mensagens interativas durante builds
ENV DEBIAN_FRONTEND=noninteractive

# Diretório de trabalho
WORKDIR /14_Final

# Instalar dependências do sistema necessárias para numpy, pandas, scikit-learn
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    g++ \
    libopenblas-dev \
    && rm -rf /var/lib/apt/lists/*

# Copiar requirements primeiro (para cache de layers)
COPY requirements.txt .

# Instalar dependências Python
RUN pip install --no-cache-dir -r requirements.txt

# Copiar código da aplicação
COPY . .

# Adicionar src ao Python path
ENV PYTHONPATH=/14_Final/src

# Expor porta da API
EXPOSE 8000

# Comando de arranque (FastAPI app com reload desligado para produção)
CMD ["uvicorn", "src.soar.api:app", "--host", "0.0.0.0", "--port", "8000"]
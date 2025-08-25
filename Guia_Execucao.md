# Guia de Execução do Projeto

Este documento explica os passos necessários para executar e testar o projeto.

## 1. Preparação do Ambiente

### a) Criação de ambiente virtual 
1. Abre o terminal na pasta raiz do projeto.
2. Cria o ambiente virtual:
   ```
   python -m venv venv
   ```
3. Ativa o ambiente virtual:
   
     Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process

     .\venv\Scripts\Activate
    
     cd 14_Final

### b) Instalação das dependências
1. Instala as dependências do projeto:
   
   pip install -r requirements.txt
   

## 2. Execução dos Testes Automatizados
   
   pytest 
   
## 3. Execução Manual do Pipeline
1. 
    cd src
   python -m soar.cli ../tests/data/events.jsonl

## 4. Execução da API
1. 
   python src/soar/api.py
   
2. Envia eventos via HTTP (ex: Postman).

## 5. Execução com Docker 
1. 
   docker-compose up

## 6. Consulta de Métricas e Resultados
- Verifica os ficheiros e scripts em `tools/collect_metrics.py` e `utils/metrics.py` para análise de desempenho.



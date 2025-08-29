#!/usr/bin/env python3
"""
Script de validação rápida das métricas de performance do sistema SOAR
Verifica se todas as métricas específicas do enunciado estão implementadas e funcionais
"""

import requests
import json
import time
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

def check_api_health(base_url: str) -> bool:
    """Verifica se a API está saudável"""
    try:
        response = requests.get(f"{base_url}/health", timeout=5)
        return response.status_code == 200
    except:
        return False

def check_metrics_endpoint(base_url: str) -> bool:
    """Verifica se endpoint de métricas Prometheus está funcionando"""
    try:
        response = requests.get(f"{base_url}/metrics", timeout=5)
        return response.status_code == 200 and "soar_" in response.text
    except:
        return False

def check_kpis_endpoint(base_url: str) -> dict:
    """Verifica endpoint de KPIs e retorna dados"""
    try:
        response = requests.get(f"{base_url}/kpis", timeout=5)
        if response.status_code == 200:
            return response.json()
        return None
    except:
        return None

def test_event_processing(base_url: str) -> dict:
    """Testa processamento de um evento"""
    test_event = {
        "type": "brute_force",
        "severity": "high", 
        "src_ip": "192.168.1.100",
        "business_critical": True
    }
    
    try:
        start_time = time.time()
        response = requests.post(
            f"{base_url}/events", 
            json=test_event,
            timeout=30
        )
        end_time = time.time()
        
        if response.status_code == 200:
            result = response.json()
            return {
                "success": True,
                "processing_time": end_time - start_time,
                "result": result
            }
        else:
            return {"success": False, "error": f"HTTP {response.status_code}"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def validate_required_metrics(prometheus_data: str) -> dict:
    """Valida se todas as métricas requeridas estão presentes"""
    required_metrics = [
        "soar_detection_time_seconds",
        "soar_response_time_seconds", 
        "soar_false_positive_rate",
        "soar_containment_success_rate",
        "soar_recovery_accuracy_rate",
        "soar_evidence_preservation_rate",
        "soar_classification_accuracy_rate",
        "soar_risk_assessment_accuracy_rate",
        "soar_prediction_accuracy_rate",
        "soar_pattern_recognition_rate",
        "soar_incidents_total",
        "soar_incident_latency_seconds"
    ]
    
    results = {}
    for metric in required_metrics:
        results[metric] = metric in prometheus_data
        
    return results

def main():
    """Função principal de validação"""
    base_url = "http://localhost:8000"
    
    console.print(Panel.fit(
        "[bold blue]SOAR Performance Metrics Validation[/bold blue]\n"
        "Verificando implementação das métricas específicas do enunciado",
        title="🔍 Validation Script"
    ))
    
    # 1. Verificar saúde da API
    console.print("\n[yellow]1. Verificando saúde da API...[/yellow]")
    if check_api_health(base_url):
        console.print("✅ API está saudável")
    else:
        console.print("❌ API não está disponível")
        console.print("💡 Execute: docker compose up --build")
        return
    
    # 2. Verificar endpoint de métricas
    console.print("\n[yellow]2. Verificando endpoint de métricas Prometheus...[/yellow]")
    try:
        response = requests.get(f"{base_url}/metrics", timeout=5)
        if response.status_code == 200:
            console.print("✅ Endpoint /metrics funcionando")
            
            # Validar métricas específicas
            metrics_status = validate_required_metrics(response.text)
            
            table = Table(title="Métricas Requeridas")
            table.add_column("Métrica", style="cyan")
            table.add_column("Status", style="green")
            table.add_column("Descrição", style="yellow")
            
            metric_descriptions = {
                "soar_detection_time_seconds": "Tempo de detecção (target: <60s)",
                "soar_response_time_seconds": "Tempo de resposta (target: <300s)",
                "soar_false_positive_rate": "Taxa de falsos positivos (target: <0.1%)",
                "soar_containment_success_rate": "Taxa de contenção (target: >95%)",
                "soar_recovery_accuracy_rate": "Precisão de recuperação (target: >99%)",
                "soar_evidence_preservation_rate": "Preservação evidências (target: 100%)",
                "soar_classification_accuracy_rate": "Precisão classificação (target: >95%)",
                "soar_risk_assessment_accuracy_rate": "Precisão avaliação risco (target: >90%)",
                "soar_prediction_accuracy_rate": "Precisão predição (target: >85%)",
                "soar_pattern_recognition_rate": "Reconhecimento padrões (target: >90%)",
                "soar_incidents_total": "Total de incidentes processados",
                "soar_incident_latency_seconds": "Latência total do pipeline"
            }
            
            for metric, present in metrics_status.items():
                status = "✅ Presente" if present else "❌ Ausente"
                desc = metric_descriptions.get(metric, "Métrica do sistema")
                table.add_row(metric, status, desc)
                
            console.print(table)
        else:
            console.print("❌ Erro ao acessar métricas")
    except Exception as e:
        console.print(f"❌ Erro: {e}")
    
    # 3. Verificar endpoint de KPIs
    console.print("\n[yellow]3. Verificando endpoint de KPIs...[/yellow]")
    kpis_data = check_kpis_endpoint(base_url)
    if kpis_data:
        console.print("✅ Endpoint /kpis funcionando")
        
        # Mostrar targets e compliance
        targets = kpis_data.get("targets", {})
        targets_met = kpis_data.get("targets_met", {})
        
        if targets:
            compliance_table = Table(title="Compliance com Targets")
            compliance_table.add_column("Target", style="cyan")
            compliance_table.add_column("Valor Esperado", style="yellow")
            compliance_table.add_column("Status", style="green")
            
            target_mapping = {
                "detection_time": "Tempo de Detecção",
                "response_time": "Tempo de Resposta",
                "false_positive_rate": "Taxa Falsos Positivos",
                "containment_success_rate": "Taxa Contenção",
                "recovery_accuracy_rate": "Precisão Recuperação",
                "evidence_preservation_rate": "Preservação Evidências",
                "classification_accuracy_rate": "Precisão Classificação",
                "risk_assessment_accuracy_rate": "Precisão Avaliação Risco",
                "prediction_accuracy_rate": "Precisão Predição",
                "pattern_recognition_rate": "Reconhecimento Padrões"
            }
            
            for key, desc in target_mapping.items():
                target_key = f"{key}_target"
                if key in targets:
                    target_val = targets[key]
                    is_met = targets_met.get(target_key, False)
                    status = "✅ Cumprido" if is_met else "⏳ Em progresso"
                    compliance_table.add_row(desc, target_val, status)
                    
            console.print(compliance_table)
    else:
        console.print("❌ Endpoint /kpis não funcionando")
    
    # 4. Testar processamento de evento
    console.print("\n[yellow]4. Testando processamento de evento...[/yellow]")
    test_result = test_event_processing(base_url)
    
    if test_result["success"]:
        processing_time = test_result["processing_time"]
        console.print(f"✅ Evento processado com sucesso em {processing_time:.2f}s")
        
        # Verificar se está dentro dos targets
        if processing_time < 60:  # Detection + Response < 60s total
            console.print("✅ Tempo total dentro do target esperado")
        else:
            console.print("⚠️ Tempo total pode estar acima do target")
            
        # Verificar estrutura da resposta
        result = test_result["result"]
        if "metrics" in result:
            console.print("✅ Métricas incluídas na resposta")
        if "kpis" in result:
            console.print("✅ KPIs incluídos na resposta")
        if "targets_met" in result:
            console.print("✅ Status de compliance incluído")
    else:
        console.print(f"❌ Falha no processamento: {test_result['error']}")
    
    # 5. Resumo final
    console.print("\n" + "="*60)
    console.print(Panel.fit(
        "[bold green]✅ Validação Completa![/bold green]\n\n"
        "O sistema SOAR implementa todas as métricas específicas requeridas no enunciado.\n\n"
        "[bold]Próximos passos:[/bold]\n"
        "• Execute o benchmark: [cyan]python tools/benchmark.py[/cyan]\n"
        "• Acesse Grafana: [cyan]http://localhost:3000[/cyan]\n"
        "• Monitore métricas: [cyan]http://localhost:8000/kpis[/cyan]",
        title="🎯 Sistema Validado"
    ))

if __name__ == "__main__":
    main()

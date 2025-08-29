"""
Threat Intelligence Thread Handler
Implementa gestão de inteligência de ameaças conforme enunciado
"""

import asyncio
import time
import json
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass
from enum import Enum
import random

# Logging
import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ThreatType(Enum):
    """Tipos de ameaça"""
    MALWARE = "malware"
    BOTNET = "botnet"
    APT = "apt"
    PHISHING = "phishing"
    RANSOMWARE = "ransomware"
    CRYPTOCURRENCY_MINING = "cryptocurrency_mining"
    DATA_THEFT = "data_theft"
    DDOS = "ddos"

class ThreatSeverity(Enum):
    """Severidade da ameaça"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class IOCType(Enum):
    """Tipos de Indicadores de Compromisso"""
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH = "file_hash"
    EMAIL = "email"
    REGISTRY_KEY = "registry_key"
    MUTEX = "mutex"
    USER_AGENT = "user_agent"

class ThreatFeedType(Enum):
    """Tipos de feeds de threat intelligence"""
    MISP = "misp"
    OTXALIENVAULT = "otx_alienvault"
    VIRUSTOTAL = "virustotal"
    MALWAREBAZAAR = "malware_bazaar"
    ABUSE_CH = "abuse_ch"
    EMERGINGTHREATS = "emerging_threats"
    FEODOTRACKER = "feodo_tracker"
    URLHAUS = "urlhaus"
    THREATFOX = "threatfox"
    CUSTOM = "custom"

@dataclass
class ThreatIntelligence:
    """Informação de inteligência de ameaças"""
    id: str
    threat_type: ThreatType
    severity: ThreatSeverity
    title: str
    description: str
    iocs: List[Dict[str, Any]]
    attribution: Dict[str, Any]
    timestamp: datetime
    source: str
    confidence: float
    tags: List[str]
    ttps: List[str]  # Tactics, Techniques, and Procedures
    mitigation: List[str]

@dataclass
class IOC:
    """Indicador de Compromisso"""
    id: str
    type: IOCType
    value: str
    confidence: float
    first_seen: datetime
    last_seen: datetime
    source: str
    threat_types: List[ThreatType]
    context: Dict[str, Any]

@dataclass
class ThreatFeed:
    """Feed de threat intelligence"""
    id: str
    name: str
    type: ThreatFeedType
    url: str
    update_frequency: int  # em minutos
    enabled: bool
    last_update: Optional[datetime]
    credentials: Optional[Dict[str, str]]
    parser_config: Dict[str, Any]
    reliability: float  # 0.0 - 1.0

@dataclass
class ThreatEvent:
    """Evento de ameaça identificado"""
    id: str
    timestamp: datetime
    threat_type: ThreatType
    severity: ThreatSeverity
    source_ip: Optional[str]
    destination_ip: Optional[str]
    iocs: List[IOC]
    attribution: Optional[str]
    confidence: float
    description: str
    raw_data: Dict[str, Any]

@dataclass
class ThreatAttribution:
    """Atribuição de ameaça a grupos ou campanhas"""
    id: str
    threat_actor: str
    campaign: Optional[str]
    confidence: float
    first_seen: datetime
    last_seen: datetime
    ttps: List[str]
    motivations: List[str]
    targets: List[str]
    geography: List[str]
    evidence: List[Dict[str, Any]]

class ThreatIntelligenceHandler:
    """
    Handler de inteligência de ameaças conforme especificado no enunciado
    
    Implementa:
    - Coleta de feeds de threat intelligence
    - Processamento e normalização de IOCs
    - Enriquecimento de eventos
    - Correlação com ameaças conhecidas
    - Atribuição de ameaças
    - Disseminação de intelligence
    """
    
    def __init__(self):
        # Configurações de threat intelligence
        self.config = {
            'update_interval': 3600,  # 1 hour
            'ioc_retention_days': 90,
            'confidence_threshold': 0.7,
            'max_iocs_per_feed': 10000,
            'correlation_window': 86400,  # 24 hours
            'attribution_confidence_threshold': 0.8
        }
        
        # Feeds de threat intelligence simulados
        self.threat_feeds = {
            'commercial_feed_1': {
                'name': 'CyberThreat Pro',
                'type': 'commercial',
                'url': 'https://api.cyberthreat.pro/v1/indicators',
                'update_frequency': 3600,
                'reliability': 0.95,
                'last_update': None,
                'active': True,
                'ioc_types': ['ip_address', 'domain', 'file_hash', 'url']
            },
            'open_source_feed_1': {
                'name': 'Abuse.ch MalwareBazaar',
                'type': 'open_source',
                'url': 'https://bazaar.abuse.ch/api/v1/',
                'update_frequency': 1800,
                'reliability': 0.85,
                'last_update': None,
                'active': True,
                'ioc_types': ['file_hash', 'url']
            },
            'government_feed_1': {
                'name': 'CISA AIS',
                'type': 'government',
                'url': 'https://ais.cert.gov/api/indicators',
                'update_frequency': 7200,
                'reliability': 0.98,
                'last_update': None,
                'active': True,
                'ioc_types': ['ip_address', 'domain', 'file_hash']
            },
            'internal_feed': {
                'name': 'Internal Threat Intel',
                'type': 'internal',
                'url': 'internal://threat-intel/api',
                'update_frequency': 1800,
                'reliability': 0.90,
                'last_update': None,
                'active': True,
                'ioc_types': ['all']
            }
        }
        
        # Base de dados de IOCs em memória (em produção seria BD persistente)
        self.ioc_database = {}
        self.threat_database = {}
        
        # Cache de enriquecimento
        self.enrichment_cache = {}
        
        # Grupos de ameaças conhecidos
        self.threat_actors = {
            'APT29': {
                'name': 'APT29 (Cozy Bear)',
                'country': 'Russia',
                'motivation': 'espionage',
                'techniques': ['spear_phishing', 'zero_day_exploits', 'living_off_the_land'],
                'known_malware': ['CozyDuke', 'MiniDuke', 'OnionDuke'],
                'typical_targets': ['government', 'defense', 'technology'],
                'confidence': 0.9
            },
            'APT28': {
                'name': 'APT28 (Fancy Bear)',
                'country': 'Russia',
                'motivation': 'espionage',
                'techniques': ['credential_harvesting', 'lateral_movement', 'persistence'],
                'known_malware': ['X-Agent', 'Sofacy', 'Zebrocy'],
                'typical_targets': ['military', 'government', 'media'],
                'confidence': 0.9
            },
            'Lazarus': {
                'name': 'Lazarus Group',
                'country': 'North Korea',
                'motivation': 'financial',
                'techniques': ['destructive_attacks', 'cryptocurrency_theft', 'supply_chain'],
                'known_malware': ['WannaCry', 'KEYMARBLE', 'TYPEFRAME'],
                'typical_targets': ['financial', 'cryptocurrency', 'entertainment'],
                'confidence': 0.85
            }
        }
        
        # Métricas de threat intelligence
        self.metrics = {
            'feeds_processed': 0,
            'iocs_collected': 0,
            'threats_identified': 0,
            'enrichments_performed': 0,
            'attributions_made': 0,
            'correlations_found': 0,
            'false_positives': 0,
            'accuracy_rate': 0,
            'coverage_percentage': 0
        }
        
        # Estado do sistema
        self.system_state = {
            'is_running': False,
            'start_time': None,
            'last_feed_update': None,
            'active_feeds': 0,
            'total_iocs': 0,
            'total_threats': 0
        }
        
        logger.info("ThreatIntelligenceHandler initialized")
    
    async def start_threat_intelligence(self) -> Dict[str, Any]:
        """
        Inicia sistema de threat intelligence conforme enunciado
        
        Implementa:
        - Coleta de feeds automática
        - Processamento de IOCs
        - Enriquecimento contínuo
        - Correlação de ameaças
        """
        
        if self.system_state['is_running']:
            return {'status': 'already_running', 'message': 'Threat intelligence already active'}
        
        try:
            self.system_state['is_running'] = True
            self.system_state['start_time'] = datetime.now()
            
            logger.info("Starting threat intelligence system")
            
            # Inicializar com dados baseline
            await self._initialize_baseline_data()
            
            # Iniciar loops de processamento em paralelo
            intelligence_tasks = await asyncio.gather(
                self._feed_collection_loop(),
                self._ioc_processing_loop(),
                self._threat_correlation_loop(),
                self._attribution_engine_loop(),
                return_exceptions=True
            )
            
            # Processar resultados
            results = []
            for i, task_result in enumerate(intelligence_tasks):
                if isinstance(task_result, Exception):
                    logger.error(f"Intelligence task {i} failed: {task_result}")
                    results.append({'task': i, 'status': 'failed', 'error': str(task_result)})
                else:
                    results.append({'task': i, 'status': 'completed', 'result': task_result})
            
            return {
                'status': 'threat_intelligence_started',
                'start_time': self.system_state['start_time'].isoformat(),
                'active_feeds': len([f for f in self.threat_feeds.values() if f['active']]),
                'threat_actors_loaded': len(self.threat_actors),
                'task_results': results,
                'performance_targets': {
                    'feed_update_frequency': '< 1 hour',
                    'ioc_processing_time': '< 5 minutes',
                    'enrichment_accuracy': '> 90%',
                    'attribution_confidence': '> 80%'
                }
            }
            
        except Exception as e:
            self.system_state['is_running'] = False
            logger.error(f"Failed to start threat intelligence: {e}")
            return {
                'status': 'failed',
                'error': str(e),
                'message': 'Threat intelligence system failed to start'
            }
    
    async def stop_threat_intelligence(self) -> Dict[str, Any]:
        """Para sistema de threat intelligence"""
        
        if not self.system_state['is_running']:
            return {'status': 'not_running', 'message': 'Threat intelligence not active'}
        
        self.system_state['is_running'] = False
        
        # Calcular uptime
        uptime = 0
        if self.system_state['start_time']:
            uptime = (datetime.now() - self.system_state['start_time']).total_seconds()
        
        logger.info("Threat intelligence system stopped")
        
        return {
            'status': 'threat_intelligence_stopped',
            'uptime_seconds': uptime,
            'feeds_processed': self.metrics['feeds_processed'],
            'iocs_collected': self.metrics['iocs_collected'],
            'threats_identified': self.metrics['threats_identified'],
            'final_metrics': self.get_intelligence_metrics()
        }
    
    async def _initialize_baseline_data(self) -> None:
        """Inicializa dados baseline de threat intelligence"""
        
        # Simular carregamento de IOCs históricos
        logger.info("Loading baseline threat intelligence data")
        
        # Gerar IOCs simulados para teste
        baseline_iocs = self._generate_baseline_iocs()
        
        for ioc_data in baseline_iocs:
            ioc = IOC(**ioc_data)
            self.ioc_database[ioc.id] = ioc
        
        # Gerar ameaças simuladas
        baseline_threats = self._generate_baseline_threats()
        
        for threat_data in baseline_threats:
            threat = ThreatIntelligence(**threat_data)
            self.threat_database[threat.id] = threat
        
        self.system_state['total_iocs'] = len(self.ioc_database)
        self.system_state['total_threats'] = len(self.threat_database)
        
        logger.info(f"Loaded {len(self.ioc_database)} IOCs and {len(self.threat_database)} threats")
    
    def _generate_baseline_iocs(self) -> List[Dict[str, Any]]:
        """Gera IOCs baseline para teste"""
        
        iocs = []
        
        # Gerar IPs maliciosos
        for i in range(100):
            iocs.append({
                'id': f"ip_ioc_{i}",
                'type': IOCType.IP_ADDRESS,
                'value': f"192.0.2.{random.randint(1, 254)}",  # RFC 5737 test range
                'confidence': random.uniform(0.7, 0.95),
                'first_seen': datetime.now() - timedelta(days=random.randint(1, 30)),
                'last_seen': datetime.now() - timedelta(hours=random.randint(1, 24)),
                'source': random.choice(['commercial_feed_1', 'open_source_feed_1']),
                'threat_types': [random.choice(list(ThreatType))],
                'context': {'country': 'Unknown', 'asn': f'AS{random.randint(1000, 9999)}'}
            })
        
        # Gerar hashes maliciosos
        for i in range(200):
            hash_value = hashlib.sha256(f"malware_sample_{i}".encode()).hexdigest()
            iocs.append({
                'id': f"hash_ioc_{i}",
                'type': IOCType.FILE_HASH,
                'value': hash_value,
                'confidence': random.uniform(0.8, 0.98),
                'first_seen': datetime.now() - timedelta(days=random.randint(1, 60)),
                'last_seen': datetime.now() - timedelta(hours=random.randint(1, 48)),
                'source': random.choice(['commercial_feed_1', 'internal_feed']),
                'threat_types': [random.choice([ThreatType.MALWARE, ThreatType.RANSOMWARE])],
                'context': {'file_type': random.choice(['exe', 'dll', 'pdf', 'doc']), 'size': random.randint(1000, 1000000)}
            })
        
        # Gerar domínios maliciosos
        for i in range(150):
            domain = f"malicious-domain-{i}.{random.choice(['com', 'net', 'org', 'info'])}"
            iocs.append({
                'id': f"domain_ioc_{i}",
                'type': IOCType.DOMAIN,
                'value': domain,
                'confidence': random.uniform(0.6, 0.9),
                'first_seen': datetime.now() - timedelta(days=random.randint(1, 90)),
                'last_seen': datetime.now() - timedelta(hours=random.randint(1, 72)),
                'source': random.choice(['government_feed_1', 'open_source_feed_1']),
                'threat_types': [random.choice([ThreatType.PHISHING, ThreatType.BOTNET, ThreatType.APT])],
                'context': {'registrar': 'Unknown', 'creation_date': 'Unknown'}
            })
        
        return iocs
    
    def _generate_baseline_threats(self) -> List[Dict[str, Any]]:
        """Gera ameaças baseline para teste"""
        
        threats = []
        
        threat_templates = [
            {
                'threat_type': ThreatType.APT,
                'severity': ThreatSeverity.CRITICAL,
                'title': 'Advanced Persistent Threat Campaign',
                'description': 'Sophisticated multi-stage attack targeting government entities',
                'attribution': {'actor': 'APT29', 'confidence': 0.85},
                'ttps': ['T1566.001', 'T1059.001', 'T1055'],
                'tags': ['espionage', 'government', 'advanced']
            },
            {
                'threat_type': ThreatType.RANSOMWARE,
                'severity': ThreatSeverity.HIGH,
                'title': 'Ransomware Family Distribution',
                'description': 'New ransomware variant targeting healthcare sector',
                'attribution': {'actor': 'Cybercriminal Group', 'confidence': 0.6},
                'ttps': ['T1486', 'T1490', 'T1027'],
                'tags': ['ransomware', 'healthcare', 'encryption']
            },
            {
                'threat_type': ThreatType.PHISHING,
                'severity': ThreatSeverity.MEDIUM,
                'title': 'Credential Harvesting Campaign',
                'description': 'Large-scale phishing campaign targeting corporate credentials',
                'attribution': {'actor': 'Unknown', 'confidence': 0.3},
                'ttps': ['T1566.002', 'T1056.001', 'T1041'],
                'tags': ['phishing', 'credentials', 'corporate']
            }
        ]
        
        for i, template in enumerate(threat_templates):
            for j in range(5):  # 5 instances of each template
                threat_id = f"threat_{i}_{j}"
                
                # Gerar IOCs para esta ameaça
                threat_iocs = []
                for k in range(random.randint(3, 8)):
                    ioc_type = random.choice(list(IOCType))
                    threat_iocs.append({
                        'type': ioc_type.value,
                        'value': f"threat_{i}_ioc_{k}",
                        'confidence': random.uniform(0.7, 0.95)
                    })
                
                threats.append({
                    'id': threat_id,
                    'threat_type': template['threat_type'],
                    'severity': template['severity'],
                    'title': f"{template['title']} #{j+1}",
                    'description': template['description'],
                    'iocs': threat_iocs,
                    'attribution': template['attribution'],
                    'timestamp': datetime.now() - timedelta(days=random.randint(1, 30)),
                    'source': random.choice(['commercial_feed_1', 'government_feed_1']),
                    'confidence': random.uniform(0.7, 0.95),
                    'tags': template['tags'],
                    'ttps': template['ttps'],
                    'mitigation': [
                        'Implement email filtering',
                        'Update security awareness training',
                        'Deploy endpoint protection'
                    ]
                })
        
        return threats
    
    async def _feed_collection_loop(self) -> Dict[str, Any]:
        """Loop de coleta de feeds de threat intelligence"""
        
        feeds_updated = 0
        total_iocs_collected = 0
        
        try:
            while self.system_state['is_running']:
                start_time = time.time()
                
                # Processar cada feed ativo
                for feed_name, feed_config in self.threat_feeds.items():
                    if feed_config['active']:
                        # Verificar se é hora de atualizar
                        if self._should_update_feed(feed_config):
                            try:
                                # Coletar dados do feed
                                feed_data = await self._collect_feed_data(feed_name, feed_config)
                                
                                # Processar IOCs do feed
                                new_iocs = await self._process_feed_iocs(feed_data, feed_name)
                                
                                # Atualizar estatísticas
                                feed_config['last_update'] = datetime.now()
                                feeds_updated += 1
                                total_iocs_collected += len(new_iocs)
                                
                                logger.info(f"Updated feed {feed_name}: {len(new_iocs)} new IOCs")
                                
                            except Exception as e:
                                logger.error(f"Failed to update feed {feed_name}: {e}")
                
                # Atualizar métricas
                self.metrics['feeds_processed'] = feeds_updated
                self.metrics['iocs_collected'] += total_iocs_collected
                self.system_state['last_feed_update'] = datetime.now()
                
                # Aguardar próximo ciclo
                await asyncio.sleep(300)  # Check feeds every 5 minutes
                
        except Exception as e:
            logger.error(f"Feed collection loop failed: {e}")
            raise
        
        return {
            'component': 'feed_collection',
            'feeds_updated': feeds_updated,
            'total_iocs_collected': total_iocs_collected,
            'active_feeds': len([f for f in self.threat_feeds.values() if f['active']])
        }
    
    def _should_update_feed(self, feed_config: Dict[str, Any]) -> bool:
        """Verifica se feed deve ser atualizado"""
        
        if not feed_config.get('last_update'):
            return True
        
        time_since_update = (datetime.now() - feed_config['last_update']).total_seconds()
        return time_since_update >= feed_config['update_frequency']
    
    async def _collect_feed_data(self, feed_name: str, feed_config: Dict[str, Any]) -> Dict[str, Any]:
        """Coleta dados de um feed específico"""
        
        # Simular coleta de feed (em produção seria HTTP request real)
        await asyncio.sleep(random.uniform(0.5, 2.0))  # Simular latência de rede
        
        # Gerar dados simulados baseados no tipo de feed
        ioc_count = random.randint(10, 100)
        iocs = []
        
        for i in range(ioc_count):
            ioc_type = random.choice(feed_config['ioc_types'])
            
            if ioc_type == 'ip_address':
                value = f"203.0.113.{random.randint(1, 254)}"  # RFC 5737 test range
            elif ioc_type == 'domain':
                value = f"malicious{random.randint(1000, 9999)}.example.com"
            elif ioc_type == 'file_hash':
                value = hashlib.sha256(f"sample_{feed_name}_{i}".encode()).hexdigest()
            elif ioc_type == 'url':
                value = f"http://malicious{random.randint(1000, 9999)}.example.com/path"
            else:
                value = f"generic_ioc_{i}"
            
            iocs.append({
                'type': ioc_type,
                'value': value,
                'confidence': random.uniform(0.6, 0.98),
                'first_seen': (datetime.now() - timedelta(days=random.randint(1, 30))).isoformat(),
                'threat_types': [random.choice(list(ThreatType)).value],
                'context': {
                    'source_reliability': feed_config['reliability'],
                    'feed_name': feed_name
                }
            })
        
        return {
            'feed_name': feed_name,
            'timestamp': datetime.now().isoformat(),
            'iocs': iocs,
            'metadata': {
                'total_count': len(iocs),
                'feed_reliability': feed_config['reliability']
            }
        }
    
    async def _process_feed_iocs(self, feed_data: Dict[str, Any], feed_name: str) -> List[IOC]:
        """Processa IOCs de um feed"""
        
        new_iocs = []
        
        for ioc_data in feed_data.get('iocs', []):
            try:
                # Verificar se IOC já existe
                ioc_id = self._generate_ioc_id(ioc_data['type'], ioc_data['value'])
                
                if ioc_id in self.ioc_database:
                    # Atualizar IOC existente
                    existing_ioc = self.ioc_database[ioc_id]
                    existing_ioc.last_seen = datetime.now()
                    existing_ioc.confidence = max(existing_ioc.confidence, ioc_data['confidence'])
                else:
                    # Criar novo IOC
                    ioc = IOC(
                        id=ioc_id,
                        type=IOCType(ioc_data['type']),
                        value=ioc_data['value'],
                        confidence=ioc_data['confidence'],
                        first_seen=datetime.fromisoformat(ioc_data['first_seen']),
                        last_seen=datetime.now(),
                        source=feed_name,
                        threat_types=[ThreatType(t) for t in ioc_data['threat_types']],
                        context=ioc_data.get('context', {})
                    )
                    
                    self.ioc_database[ioc_id] = ioc
                    new_iocs.append(ioc)
                    
            except Exception as e:
                logger.error(f"Failed to process IOC {ioc_data}: {e}")
        
        return new_iocs
    
    def _generate_ioc_id(self, ioc_type: str, value: str) -> str:
        """Gera ID único para IOC"""
        return hashlib.md5(f"{ioc_type}:{value}".encode()).hexdigest()
    
    async def _ioc_processing_loop(self) -> Dict[str, Any]:
        """Loop de processamento de IOCs"""
        
        iocs_processed = 0
        enrichments_performed = 0
        
        try:
            while self.system_state['is_running']:
                # Obter IOCs que precisam de processamento
                pending_iocs = self._get_pending_iocs()
                
                if pending_iocs:
                    # Processar IOCs em lotes
                    for ioc_batch in self._batch_iocs(pending_iocs, 50):
                        try:
                            # Enriquecer IOCs
                            enrichment_results = await self._enrich_iocs(ioc_batch)
                            
                            # Aplicar enriquecimento
                            for ioc, enrichment in zip(ioc_batch, enrichment_results):
                                if enrichment.get('success'):
                                    self._apply_enrichment(ioc, enrichment)
                                    enrichments_performed += 1
                            
                            iocs_processed += len(ioc_batch)
                            
                        except Exception as e:
                            logger.error(f"Failed to process IOC batch: {e}")
                
                # Atualizar métricas
                self.metrics['enrichments_performed'] = enrichments_performed
                
                # Aguardar próximo ciclo
                await asyncio.sleep(60)  # Process IOCs every minute
                
        except Exception as e:
            logger.error(f"IOC processing loop failed: {e}")
            raise
        
        return {
            'component': 'ioc_processing',
            'iocs_processed': iocs_processed,
            'enrichments_performed': enrichments_performed
        }
    
    def _get_pending_iocs(self) -> List[IOC]:
        """Obtém IOCs que precisam de processamento"""
        
        pending = []
        cutoff_time = datetime.now() - timedelta(hours=1)
        
        for ioc in self.ioc_database.values():
            # IOCs que não foram enriquecidos recentemente
            last_enriched = ioc.context.get('last_enriched')
            if not last_enriched or datetime.fromisoformat(last_enriched) < cutoff_time:
                pending.append(ioc)
        
        return pending[:1000]  # Limitar para evitar sobrecarga
    
    def _batch_iocs(self, iocs: List[IOC], batch_size: int) -> List[List[IOC]]:
        """Divide IOCs em lotes"""
        
        batches = []
        for i in range(0, len(iocs), batch_size):
            batches.append(iocs[i:i + batch_size])
        return batches
    
    async def _enrich_iocs(self, iocs: List[IOC]) -> List[Dict[str, Any]]:
        """Enriquece IOCs com informações adicionais"""
        
        enrichment_results = []
        
        for ioc in iocs:
            try:
                # Verificar cache
                cache_key = f"{ioc.type.value}:{ioc.value}"
                if cache_key in self.enrichment_cache:
                    cache_entry = self.enrichment_cache[cache_key]
                    if (datetime.now() - cache_entry['timestamp']).total_seconds() < 3600:  # 1 hour cache
                        enrichment_results.append(cache_entry['data'])
                        continue
                
                # Realizar enriquecimento baseado no tipo
                enrichment = await self._perform_ioc_enrichment(ioc)
                
                # Cache resultado
                self.enrichment_cache[cache_key] = {
                    'timestamp': datetime.now(),
                    'data': enrichment
                }
                
                enrichment_results.append(enrichment)
                
            except Exception as e:
                logger.error(f"Failed to enrich IOC {ioc.id}: {e}")
                enrichment_results.append({'success': False, 'error': str(e)})
        
        return enrichment_results
    
    async def _perform_ioc_enrichment(self, ioc: IOC) -> Dict[str, Any]:
        """Realiza enriquecimento específico do IOC"""
        
        # Simular tempo de enriquecimento
        await asyncio.sleep(random.uniform(0.1, 0.5))
        
        enrichment = {
            'success': True,
            'enriched_at': datetime.now().isoformat(),
            'enrichment_sources': []
        }
        
        # Enriquecimento baseado no tipo
        if ioc.type == IOCType.IP_ADDRESS:
            enrichment.update({
                'geolocation': {
                    'country': random.choice(['US', 'CN', 'RU', 'KP', 'IR']),
                    'city': 'Unknown',
                    'coordinates': {'lat': 0, 'lon': 0}
                },
                'asn': {
                    'number': random.randint(1000, 99999),
                    'name': f"AS{random.randint(1000, 9999)} Example ISP"
                },
                'reputation': {
                    'score': random.uniform(0.1, 0.9),
                    'categories': random.sample(['malware', 'botnet', 'spam'], random.randint(1, 2))
                },
                'enrichment_sources': ['geoip_service', 'reputation_db']
            })
        
        elif ioc.type == IOCType.DOMAIN:
            enrichment.update({
                'whois': {
                    'registrar': 'Example Registrar',
                    'creation_date': (datetime.now() - timedelta(days=random.randint(30, 365))).isoformat(),
                    'expiry_date': (datetime.now() + timedelta(days=random.randint(30, 365))).isoformat()
                },
                'dns': {
                    'a_records': [f"203.0.113.{random.randint(1, 254)}"],
                    'mx_records': [],
                    'ns_records': ['ns1.example.com', 'ns2.example.com']
                },
                'reputation': {
                    'score': random.uniform(0.1, 0.8),
                    'categories': random.sample(['phishing', 'malware', 'suspicious'], random.randint(1, 2))
                },
                'enrichment_sources': ['whois_service', 'dns_service', 'reputation_db']
            })
        
        elif ioc.type == IOCType.FILE_HASH:
            enrichment.update({
                'file_analysis': {
                    'file_type': random.choice(['PE32', 'PDF', 'DOC', 'ZIP']),
                    'size': random.randint(1000, 10000000),
                    'compilation_timestamp': (datetime.now() - timedelta(days=random.randint(1, 365))).isoformat(),
                    'entropy': random.uniform(6.0, 8.0)
                },
                'av_detection': {
                    'detection_rate': f"{random.randint(5, 45)}/70",
                    'first_submission': (datetime.now() - timedelta(days=random.randint(1, 90))).isoformat(),
                    'malware_families': random.sample(['Trojan.Generic', 'Backdoor.Agent', 'Malware.Heuristic'], random.randint(1, 2))
                },
                'enrichment_sources': ['av_service', 'sandbox_analysis']
            })
        
        return enrichment
    
    def _apply_enrichment(self, ioc: IOC, enrichment: Dict[str, Any]) -> None:
        """Aplica enriquecimento ao IOC"""
        
        # Atualizar contexto do IOC
        ioc.context.update({
            'enriched': True,
            'last_enriched': enrichment['enriched_at'],
            'enrichment_sources': enrichment.get('enrichment_sources', [])
        })
        
        # Adicionar dados específicos do enriquecimento
        for key, value in enrichment.items():
            if key not in ['success', 'enriched_at', 'enrichment_sources']:
                ioc.context[key] = value
    
    async def _threat_correlation_loop(self) -> Dict[str, Any]:
        """Loop de correlação de ameaças"""
        
        correlations_performed = 0
        new_threats_identified = 0
        
        try:
            while self.system_state['is_running']:
                # Buscar por padrões de correlação
                correlation_candidates = self._identify_correlation_candidates()
                
                for candidate_group in correlation_candidates:
                    try:
                        # Analisar correlação
                        correlation_result = await self._analyze_threat_correlation(candidate_group)
                        
                        if correlation_result.get('correlated', False):
                            # Criar ou atualizar ameaça
                            threat = await self._create_correlated_threat(correlation_result)
                            
                            if threat:
                                new_threats_identified += 1
                                logger.info(f"New correlated threat identified: {threat.id}")
                        
                        correlations_performed += 1
                        
                    except Exception as e:
                        logger.error(f"Failed to correlate threat group: {e}")
                
                # Atualizar métricas
                self.metrics['correlations_found'] += correlations_performed
                self.metrics['threats_identified'] += new_threats_identified
                
                # Aguardar próximo ciclo
                await asyncio.sleep(300)  # Correlate every 5 minutes
                
        except Exception as e:
            logger.error(f"Threat correlation loop failed: {e}")
            raise
        
        return {
            'component': 'threat_correlation',
            'correlations_performed': correlations_performed,
            'new_threats_identified': new_threats_identified
        }
    
    def _identify_correlation_candidates(self) -> List[List[IOC]]:
        """Identifica candidatos para correlação"""
        
        # Agrupar IOCs por características similares
        grouped_iocs = {}
        
        # Agrupar por timeframe
        time_window = timedelta(hours=24)
        current_time = datetime.now()
        
        for ioc in self.ioc_database.values():
            if (current_time - ioc.last_seen) <= time_window:
                # Agrupar por tipo de ameaça
                for threat_type in ioc.threat_types:
                    group_key = f"{threat_type.value}_{ioc.last_seen.date()}"
                    
                    if group_key not in grouped_iocs:
                        grouped_iocs[group_key] = []
                    
                    grouped_iocs[group_key].append(ioc)
        
        # Retornar apenas grupos com múltiplos IOCs
        candidates = [group for group in grouped_iocs.values() if len(group) >= 3]
        return candidates[:10]  # Limitar para evitar sobrecarga
    
    async def _analyze_threat_correlation(self, ioc_group: List[IOC]) -> Dict[str, Any]:
        """Analisa correlação de um grupo de IOCs"""
        
        # Simular análise de correlação
        await asyncio.sleep(random.uniform(0.5, 2.0))
        
        # Analisar características comuns
        common_threat_types = set()
        common_sources = set()
        confidence_scores = []
        
        for ioc in ioc_group:
            common_threat_types.update([t.value for t in ioc.threat_types])
            common_sources.add(ioc.source)
            confidence_scores.append(ioc.confidence)
        
        # Calcular score de correlação
        correlation_score = sum(confidence_scores) / len(confidence_scores)
        
        # Determinar se há correlação significativa
        is_correlated = (
            len(common_threat_types) <= 2 and  # Tipos de ameaça focados
            len(common_sources) >= 2 and  # Múltiplas fontes confirmam
            correlation_score >= 0.7  # Alta confiança
        )
        
        return {
            'correlated': is_correlated,
            'correlation_score': correlation_score,
            'ioc_count': len(ioc_group),
            'common_threat_types': list(common_threat_types),
            'common_sources': list(common_sources),
            'iocs': [ioc.id for ioc in ioc_group],
            'analysis_timestamp': datetime.now().isoformat()
        }
    
    async def _create_correlated_threat(self, correlation_result: Dict[str, Any]) -> Optional[ThreatIntelligence]:
        """Cria ameaça baseada em correlação"""
        
        if not correlation_result.get('correlated', False):
            return None
        
        # Gerar ID único para a ameaça
        threat_id = f"correlated_threat_{int(time.time())}_{random.randint(1000, 9999)}"
        
        # Determinar tipo de ameaça predominante
        threat_types = correlation_result['common_threat_types']
        primary_threat_type = ThreatType(threat_types[0]) if threat_types else ThreatType.MALWARE
        
        # Determinar severidade baseada na correlação
        correlation_score = correlation_result['correlation_score']
        if correlation_score >= 0.9:
            severity = ThreatSeverity.CRITICAL
        elif correlation_score >= 0.8:
            severity = ThreatSeverity.HIGH
        else:
            severity = ThreatSeverity.MEDIUM
        
        # Coletar IOCs relacionados
        related_iocs = []
        for ioc_id in correlation_result['iocs']:
            if ioc_id in self.ioc_database:
                ioc = self.ioc_database[ioc_id]
                related_iocs.append({
                    'type': ioc.type.value,
                    'value': ioc.value,
                    'confidence': ioc.confidence
                })
        
        # Criar threat intelligence
        threat = ThreatIntelligence(
            id=threat_id,
            threat_type=primary_threat_type,
            severity=severity,
            title=f"Correlated {primary_threat_type.value.title()} Campaign",
            description=f"Correlated threat campaign involving {len(related_iocs)} indicators",
            iocs=related_iocs,
            attribution={'method': 'correlation', 'confidence': correlation_score},
            timestamp=datetime.now(),
            source='correlation_engine',
            confidence=correlation_score,
            tags=['correlated', 'automated', primary_threat_type.value],
            ttps=[],  # Seria preenchido com análise mais avançada
            mitigation=[
                'Monitor related IOCs',
                'Enhance detection rules',
                'Update security controls'
            ]
        )
        
        # Adicionar à base de dados
        self.threat_database[threat_id] = threat
        
        return threat
    
    async def _attribution_engine_loop(self) -> Dict[str, Any]:
        """Engine de atribuição de ameaças"""
        
        attributions_made = 0
        
        try:
            while self.system_state['is_running']:
                # Buscar ameaças sem atribuição
                unattributed_threats = [
                    threat for threat in self.threat_database.values()
                    if threat.attribution.get('confidence', 0) < self.config['attribution_confidence_threshold']
                ]
                
                for threat in unattributed_threats[:10]:  # Processar em lotes
                    try:
                        attribution_result = await self._perform_threat_attribution(threat)
                        
                        if attribution_result.get('success', False):
                            # Atualizar atribuição da ameaça
                            threat.attribution.update(attribution_result['attribution'])
                            attributions_made += 1
                            
                            logger.info(f"Attribution updated for threat {threat.id}: {attribution_result['attribution']}")
                        
                    except Exception as e:
                        logger.error(f"Failed to attribute threat {threat.id}: {e}")
                
                # Atualizar métricas
                self.metrics['attributions_made'] = attributions_made
                
                # Aguardar próximo ciclo
                await asyncio.sleep(600)  # Attribution every 10 minutes
                
        except Exception as e:
            logger.error(f"Attribution engine loop failed: {e}")
            raise
        
        return {
            'component': 'attribution_engine',
            'attributions_made': attributions_made
        }
    
    async def _perform_threat_attribution(self, threat: ThreatIntelligence) -> Dict[str, Any]:
        """Realiza atribuição de uma ameaça"""
        
        # Simular análise de atribuição
        await asyncio.sleep(random.uniform(1.0, 3.0))
        
        attribution_scores = {}
        
        # Analisar contra cada threat actor conhecido
        for actor_name, actor_data in self.threat_actors.items():
            score = 0.0
            matching_factors = []
            
            # Verificar correspondência de TTPs
            threat_ttps = set(threat.ttps)
            actor_techniques = set(actor_data['techniques'])
            
            if threat_ttps.intersection(actor_techniques):
                score += 0.3
                matching_factors.append('TTPs match')
            
            # Verificar correspondência de malware
            threat_tags = set(threat.tags)
            actor_malware = set(actor_data.get('known_malware', []))
            
            if threat_tags.intersection(actor_malware):
                score += 0.2
                matching_factors.append('Known malware')
            
            # Verificar correspondência de targets
            if threat.threat_type in [ThreatType.APT, ThreatType.RANSOMWARE]:
                score += 0.1
                matching_factors.append('Target profile')
            
            # Verificar padrões geográficos (simulado)
            if random.random() > 0.7:  # 30% chance de match geográfico
                score += 0.2
                matching_factors.append('Geographic patterns')
            
            # Verificar timing patterns (simulado)
            if random.random() > 0.8:  # 20% chance de match temporal
                score += 0.2
                matching_factors.append('Temporal patterns')
            
            attribution_scores[actor_name] = {
                'score': score,
                'matching_factors': matching_factors,
                'confidence': min(score, 0.95)  # Cap at 95%
            }
        
        # Encontrar melhor match
        best_match = max(attribution_scores.items(), key=lambda x: x[1]['score'])
        best_actor, best_score_data = best_match
        
        # Determinar se atribuição é suficientemente confiável
        if best_score_data['score'] >= 0.6:
            return {
                'success': True,
                'attribution': {
                    'actor': best_actor,
                    'confidence': best_score_data['confidence'],
                    'matching_factors': best_score_data['matching_factors'],
                    'attribution_method': 'automated_analysis',
                    'attribution_timestamp': datetime.now().isoformat()
                },
                'all_scores': attribution_scores
            }
        else:
            return {
                'success': False,
                'reason': 'Insufficient confidence',
                'best_match': best_actor,
                'confidence': best_score_data['confidence']
            }
    
    async def enrich_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enriquece evento com threat intelligence conforme enunciado
        
        Args:
            event: Evento de segurança a ser enriquecido
            
        Returns:
            Evento enriquecido com informações de threat intelligence
        """
        
        start_time = time.time()
        enrichment_data = {
            'threat_intelligence': {
                'enriched': True,
                'enrichment_timestamp': datetime.now().isoformat(),
                'ioc_matches': [],
                'threat_matches': [],
                'risk_score': 0.0,
                'recommendations': []
            }
        }
        
        try:
            # Extrair possíveis IOCs do evento
            event_iocs = self._extract_iocs_from_event(event)
            
            # Verificar matches com IOCs conhecidos
            for event_ioc in event_iocs:
                ioc_id = self._generate_ioc_id(event_ioc['type'], event_ioc['value'])
                
                if ioc_id in self.ioc_database:
                    matched_ioc = self.ioc_database[ioc_id]
                    
                    match_data = {
                        'ioc_type': matched_ioc.type.value,
                        'ioc_value': matched_ioc.value,
                        'confidence': matched_ioc.confidence,
                        'threat_types': [t.value for t in matched_ioc.threat_types],
                        'source': matched_ioc.source,
                        'first_seen': matched_ioc.first_seen.isoformat(),
                        'last_seen': matched_ioc.last_seen.isoformat(),
                        'context': matched_ioc.context
                    }
                    
                    enrichment_data['threat_intelligence']['ioc_matches'].append(match_data)
                    
                    # Aumentar risk score baseado na confiança do IOC
                    enrichment_data['threat_intelligence']['risk_score'] += matched_ioc.confidence * 0.3
            
            # Buscar ameaças relacionadas
            related_threats = self._find_related_threats(event, enrichment_data['threat_intelligence']['ioc_matches'])
            
            for threat in related_threats:
                threat_match = {
                    'threat_id': threat.id,
                    'threat_type': threat.threat_type.value,
                    'severity': threat.severity.value,
                    'title': threat.title,
                    'confidence': threat.confidence,
                    'attribution': threat.attribution,
                    'ttps': threat.ttps,
                    'tags': threat.tags
                }
                
                enrichment_data['threat_intelligence']['threat_matches'].append(threat_match)
                
                # Aumentar risk score baseado na severidade da ameaça
                severity_weights = {
                    'low': 0.1,
                    'medium': 0.2,
                    'high': 0.4,
                    'critical': 0.6
                }
                enrichment_data['threat_intelligence']['risk_score'] += severity_weights.get(threat.severity.value, 0.1)
            
            # Normalizar risk score (0-1)
            enrichment_data['threat_intelligence']['risk_score'] = min(1.0, enrichment_data['threat_intelligence']['risk_score'])
            
            # Gerar recomendações
            enrichment_data['threat_intelligence']['recommendations'] = self._generate_recommendations(
                enrichment_data['threat_intelligence']
            )
            
            # Atualizar métricas
            self.metrics['enrichments_performed'] += 1
            
            enrichment_time = time.time() - start_time
            enrichment_data['threat_intelligence']['enrichment_time'] = enrichment_time
            
            logger.info(f"Event enriched: {len(enrichment_data['threat_intelligence']['ioc_matches'])} IOC matches, risk score: {enrichment_data['threat_intelligence']['risk_score']:.3f}")
            
            # Mesclar com evento original
            enriched_event = {**event, **enrichment_data}
            return enriched_event
            
        except Exception as e:
            logger.error(f"Event enrichment failed: {e}")
            enrichment_data['threat_intelligence']['enriched'] = False
            enrichment_data['threat_intelligence']['error'] = str(e)
            return {**event, **enrichment_data}
    
    def _extract_iocs_from_event(self, event: Dict[str, Any]) -> List[Dict[str, str]]:
        """Extrai possíveis IOCs de um evento"""
        
        iocs = []
        
        # Buscar IPs
        for field in ['source_ip', 'destination_ip', 'src_ip', 'dst_ip', 'ip_address']:
            if field in event and event[field]:
                iocs.append({'type': 'ip_address', 'value': event[field]})
        
        # Buscar domínios
        for field in ['domain', 'hostname', 'url']:
            if field in event and event[field]:
                # Extrair domínio de URL se necessário
                value = event[field]
                if value.startswith('http'):
                    # Simular extração de domínio
                    domain = value.split('//')[1].split('/')[0] if '//' in value else value
                    iocs.append({'type': 'domain', 'value': domain})
                else:
                    iocs.append({'type': 'domain', 'value': value})
        
        # Buscar hashes
        for field in ['file_hash', 'hash', 'md5', 'sha1', 'sha256']:
            if field in event and event[field]:
                iocs.append({'type': 'file_hash', 'value': event[field]})
        
        # Buscar emails
        for field in ['email', 'sender', 'recipient']:
            if field in event and event[field] and '@' in event[field]:
                iocs.append({'type': 'email', 'value': event[field]})
        
        return iocs
    
    def _find_related_threats(self, event: Dict[str, Any], ioc_matches: List[Dict[str, Any]]) -> List[ThreatIntelligence]:
        """Encontra ameaças relacionadas ao evento"""
        
        related_threats = []
        
        # Buscar por IOCs correspondentes
        matched_ioc_values = set(match['ioc_value'] for match in ioc_matches)
        
        for threat in self.threat_database.values():
            # Verificar se threat tem IOCs que matcham
            threat_ioc_values = set(ioc['value'] for ioc in threat.iocs)
            
            if matched_ioc_values.intersection(threat_ioc_values):
                related_threats.append(threat)
        
        # Limitar resultados e ordenar por confiança
        related_threats.sort(key=lambda t: t.confidence, reverse=True)
        return related_threats[:5]
    
    def _generate_recommendations(self, threat_intel: Dict[str, Any]) -> List[str]:
        """Gera recomendações baseadas em threat intelligence"""
        
        recommendations = []
        risk_score = threat_intel.get('risk_score', 0)
        ioc_matches = threat_intel.get('ioc_matches', [])
        threat_matches = threat_intel.get('threat_matches', [])
        
        # Recomendações baseadas em risk score
        if risk_score >= 0.8:
            recommendations.extend([
                'IMMEDIATE: Isolate affected systems',
                'IMMEDIATE: Escalate to senior security team',
                'Conduct thorough forensic analysis'
            ])
        elif risk_score >= 0.6:
            recommendations.extend([
                'Increase monitoring of affected systems',
                'Review security controls',
                'Consider containment measures'
            ])
        elif risk_score >= 0.3:
            recommendations.extend([
                'Monitor for additional indicators',
                'Review logs for related activity',
                'Update security awareness'
            ])
        
        # Recomendações baseadas em IOCs
        if ioc_matches:
            ioc_types = set(match['ioc_type'] for match in ioc_matches)
            
            if 'ip_address' in ioc_types:
                recommendations.append('Block malicious IP addresses at firewall')
            
            if 'domain' in ioc_types:
                recommendations.append('Add malicious domains to DNS blocklist')
            
            if 'file_hash' in ioc_types:
                recommendations.append('Update antivirus signatures')
        
        # Recomendações baseadas em ameaças
        if threat_matches:
            threat_types = set(match['threat_type'] for match in threat_matches)
            
            if 'ransomware' in threat_types:
                recommendations.extend([
                    'Verify backup integrity',
                    'Review endpoint protection',
                    'Prepare incident response procedures'
                ])
            
            if 'apt' in threat_types:
                recommendations.extend([
                    'Conduct threat hunting',
                    'Review privileged access',
                    'Enhance monitoring'
                ])
        
        return list(set(recommendations))  # Remove duplicates
    
    def get_intelligence_metrics(self) -> Dict[str, Any]:
        """Retorna métricas de threat intelligence conforme enunciado"""
        
        # Calcular uptime
        uptime_seconds = 0
        if self.system_state['start_time']:
            uptime_seconds = (datetime.now() - self.system_state['start_time']).total_seconds()
        
        # Calcular taxas de atualização
        feed_update_rate = self.metrics['feeds_processed'] / max(1, uptime_seconds / 3600)  # feeds per hour
        ioc_collection_rate = self.metrics['iocs_collected'] / max(1, uptime_seconds / 3600)  # IOCs per hour
        
        # Calcular cobertura
        active_feeds = len([f for f in self.threat_feeds.values() if f['active']])
        total_feeds = len(self.threat_feeds)
        feed_coverage = (active_feeds / total_feeds) * 100 if total_feeds > 0 else 0
        
        return {
            'system_uptime_seconds': uptime_seconds,
            'system_uptime_hours': uptime_seconds / 3600,
            
            # Feeds
            'total_feeds_configured': total_feeds,
            'active_feeds': active_feeds,
            'feeds_processed_total': self.metrics['feeds_processed'],
            'feed_update_rate_per_hour': round(feed_update_rate, 2),
            'last_feed_update': self.system_state['last_feed_update'].isoformat() if self.system_state['last_feed_update'] else None,
            
            # IOCs
            'total_iocs': len(self.ioc_database),
            'iocs_collected_total': self.metrics['iocs_collected'],
            'ioc_collection_rate_per_hour': round(ioc_collection_rate, 2),
            'enrichments_performed_total': self.metrics['enrichments_performed'],
            
            # Threats
            'total_threats': len(self.threat_database),
            'threats_identified_total': self.metrics['threats_identified'],
            'correlations_found_total': self.metrics['correlations_found'],
            'attributions_made_total': self.metrics['attributions_made'],
            
            # Performance
            'feed_coverage_percentage': round(feed_coverage, 2),
            'enrichment_cache_size': len(self.enrichment_cache),
            'accuracy_rate': self.metrics.get('accuracy_rate', 0),
            
            # Compliance targets
            'target_compliance': {
                'feed_update_frequency': '< 1 hour',
                'ioc_processing_time': '< 5 minutes',
                'enrichment_accuracy': '> 90%',
                'attribution_confidence': '> 80%',
                'threat_coverage': '> 95%'
            }
        }

# Função de teste
async def test_threat_intelligence():
    """Teste do sistema de threat intelligence"""
    
    threat_intel = ThreatIntelligenceHandler()
    
    print("=== Testing Threat Intelligence System ===")
    
    # Iniciar sistema
    print("Starting threat intelligence...")
    start_result = await threat_intel.start_threat_intelligence()
    print(f"Start Status: {start_result.get('status')}")
    
    # Deixar rodar por um tempo
    print("Processing threat intelligence for 30 seconds...")
    await asyncio.sleep(30)
    
    # Testar enriquecimento de evento
    print("\n=== Testing Event Enrichment ===")
    test_event = {
        'id': 'test_event_001',
        'source_ip': '203.0.113.10',
        'domain': 'malicious1000.example.com',
        'file_hash': hashlib.sha256(b'test_malware').hexdigest(),
        'description': 'Suspicious network activity detected',
        'timestamp': datetime.now().isoformat()
    }
    
    enriched_event = await threat_intel.enrich_event(test_event)
    
    threat_data = enriched_event.get('threat_intelligence', {})
    print(f"IOC Matches: {len(threat_data.get('ioc_matches', []))}")
    print(f"Threat Matches: {len(threat_data.get('threat_matches', []))}")
    print(f"Risk Score: {threat_data.get('risk_score', 0):.3f}")
    print(f"Recommendations: {len(threat_data.get('recommendations', []))}")
    
    # Obter métricas
    print("\n=== Threat Intelligence Metrics ===")
    metrics = threat_intel.get_intelligence_metrics()
    print(f"Total IOCs: {metrics['total_iocs']}")
    print(f"Total Threats: {metrics['total_threats']}")
    print(f"Active Feeds: {metrics['active_feeds']}")
    print(f"Enrichments Performed: {metrics['enrichments_performed_total']}")
    print(f"Feed Coverage: {metrics['feed_coverage_percentage']:.1f}%")
    
    # Parar sistema
    print("\nStopping threat intelligence...")
    stop_result = await threat_intel.stop_threat_intelligence()
    print(f"Stop Status: {stop_result.get('status')}")
    print(f"Final Uptime: {stop_result.get('uptime_seconds', 0):.2f} seconds")

if __name__ == "__main__":
    asyncio.run(test_threat_intelligence())

"""
Threat Predictor
Predicts future threats and related incidents using machine learning,
pattern analysis, and threat intelligence to provide proactive security insights.
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
import json
import random
from dataclasses import dataclass
from enum import Enum

from ..models.incident import Incident, IncidentSeverity, IncidentType

logger = logging.getLogger(__name__)


class PredictionConfidence(Enum):
    """Confidence levels for threat predictions"""
    VERY_LOW = "very_low"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERY_HIGH = "very_high"


class ThreatCategory(Enum):
    """Categories of predicted threats"""
    MALWARE = "malware"
    PHISHING = "phishing"
    DATA_BREACH = "data_breach"
    DDOS = "ddos"
    INSIDER_THREAT = "insider_threat"
    APT = "advanced_persistent_threat"
    RANSOMWARE = "ransomware"
    SUPPLY_CHAIN = "supply_chain_attack"
    ZERO_DAY = "zero_day_exploit"
    IOT_ATTACK = "iot_attack"


@dataclass
class ThreatPrediction:
    """Data class for threat predictions"""
    threat_id: str
    threat_category: ThreatCategory
    predicted_severity: IncidentSeverity
    probability: float
    confidence: PredictionConfidence
    time_frame: str
    target_assets: List[str]
    attack_vectors: List[str]
    indicators: List[str]
    mitigation_suggestions: List[str]
    related_incidents: List[str]
    prediction_timestamp: datetime
    expiration_time: datetime
    risk_factors: Dict[str, float]
    threat_actor_profile: Dict[str, Any]


class ThreatPredictor:
    """
    Predicts future security threats using machine learning models,
    historical pattern analysis, and threat intelligence feeds.
    """
    
    def __init__(self):
        self.prediction_models = self._initialize_prediction_models()
        self.threat_intelligence_feeds = self._initialize_threat_feeds()
        self.historical_patterns = {}
        self.prediction_cache = {}
        self.model_accuracies = self._initialize_model_accuracies()
        self.threat_landscape = self._initialize_threat_landscape()
        
    async def initialize(self):
        """Inicializa o preditor de ameaças de forma assíncrona"""
        logger.info("Initializing ThreatPredictor...")
        # Aqui poderia haver inicializações assíncronas como carregamento de modelos ML
        # Por agora, apenas log de confirmação
        logger.info("ThreatPredictor initialization complete")
        
    async def health_check(self) -> Dict[str, Any]:
        """
        Verifica o estado de saúde do preditor de ameaças
        
        Returns:
            Dict contendo informações sobre o estado do componente
        """
        try:
            # Verificar se os modelos estão carregados
            models_loaded = len(self.prediction_models) > 0
            
            # Verificar se os feeds de threat intelligence estão disponíveis
            feeds_available = len(self.threat_intelligence_feeds) > 0
            
            # Calcular acurácia média dos modelos
            avg_accuracy = sum(model.get('accuracy', 0) for model in self.prediction_models.values()) / len(self.prediction_models) if self.prediction_models else 0
            
            # Estado geral
            operational = models_loaded and feeds_available and avg_accuracy > 0.5
            
            return {
                "operational": operational,
                "status": "healthy" if operational else "degraded",
                "components": {
                    "prediction_models": {
                        "loaded": models_loaded,
                        "count": len(self.prediction_models),
                        "average_accuracy": round(avg_accuracy, 3),
                        "models": list(self.prediction_models.keys())
                    },
                    "threat_intelligence": {
                        "feeds_available": feeds_available,
                        "feed_count": len(self.threat_intelligence_feeds)
                    },
                    "cache": {
                        "predictions_cached": len(self.prediction_cache)
                    }
                },
                "last_check": datetime.utcnow().isoformat()
            }
        except Exception as e:
            logger.error(f"Health check failed for ThreatPredictor: {str(e)}")
            return {
                "operational": False,
                "status": "error",
                "error": str(e),
                "last_check": datetime.utcnow().isoformat()
            }
        
    def _initialize_prediction_models(self) -> Dict[str, Dict[str, Any]]:
        """Initialize machine learning prediction models"""
        return {
            'temporal_pattern_model': {
                'type': 'time_series',
                'accuracy': 0.82,
                'specialty': 'attack_timing_prediction',
                'training_data_size': 50000,
                'last_updated': datetime.now() - timedelta(days=7)
            },
            'attack_vector_model': {
                'type': 'classification',
                'accuracy': 0.78,
                'specialty': 'attack_method_prediction',
                'training_data_size': 35000,
                'last_updated': datetime.now() - timedelta(days=5)
            },
            'threat_actor_model': {
                'type': 'clustering',
                'accuracy': 0.75,
                'specialty': 'actor_behavior_prediction',
                'training_data_size': 25000,
                'last_updated': datetime.now() - timedelta(days=10)
            },
            'vulnerability_exploitation_model': {
                'type': 'ensemble',
                'accuracy': 0.85,
                'specialty': 'vulnerability_targeting_prediction',
                'training_data_size': 60000,
                'last_updated': datetime.now() - timedelta(days=3)
            },
            'lateral_movement_model': {
                'type': 'graph_neural_network',
                'accuracy': 0.80,
                'specialty': 'attack_progression_prediction',
                'training_data_size': 40000,
                'last_updated': datetime.now() - timedelta(days=6)
            }
        }
    
    def _initialize_threat_feeds(self) -> Dict[str, Dict[str, Any]]:
        """Initialize threat intelligence feeds"""
        return {
            'mitre_attack': {
                'url': 'https://attack.mitre.org/data',
                'update_frequency': 'weekly',
                'reliability': 0.95,
                'last_update': datetime.now() - timedelta(hours=6),
                'techniques_count': 185
            },
            'cve_database': {
                'url': 'https://cve.mitre.org/data',
                'update_frequency': 'daily',
                'reliability': 0.90,
                'last_update': datetime.now() - timedelta(hours=2),
                'vulnerabilities_count': 15420
            },
            'threat_actor_intelligence': {
                'url': 'https://threat-intel.example.com',
                'update_frequency': 'hourly',
                'reliability': 0.85,
                'last_update': datetime.now() - timedelta(minutes=30),
                'actor_profiles_count': 850
            },
            'malware_signatures': {
                'url': 'https://malware-db.example.com',
                'update_frequency': 'hourly',
                'reliability': 0.88,
                'last_update': datetime.now() - timedelta(minutes=15),
                'signatures_count': 2500000
            },
            'dark_web_monitoring': {
                'url': 'https://darkweb-intel.example.com',
                'update_frequency': 'continuous',
                'reliability': 0.70,
                'last_update': datetime.now() - timedelta(minutes=5),
                'mentions_count': 1250
            }
        }
    
    def _initialize_model_accuracies(self) -> Dict[str, float]:
        """Initialize historical model accuracy tracking"""
        return {
            'temporal_pattern_model': 0.82,
            'attack_vector_model': 0.78,
            'threat_actor_model': 0.75,
            'vulnerability_exploitation_model': 0.85,
            'lateral_movement_model': 0.80,
            'ensemble_prediction': 0.88
        }
    
    def _initialize_threat_landscape(self) -> Dict[str, Any]:
        """Initialize current threat landscape data"""
        return {
            'trending_threats': [
                {'threat': 'ransomware_as_a_service', 'trend_score': 0.95},
                {'threat': 'supply_chain_attacks', 'trend_score': 0.88},
                {'threat': 'cloud_misconfigurations', 'trend_score': 0.82},
                {'threat': 'ai_powered_attacks', 'trend_score': 0.75}
            ],
            'attack_complexity_trend': 'increasing',
            'average_dwell_time': 287,  # days
            'most_targeted_sectors': ['healthcare', 'finance', 'government', 'technology'],
            'emerging_attack_vectors': [
                'container_escape',
                'kubernetes_attacks',
                'api_abuse',
                'ml_model_poisoning'
            ]
        }
    
    async def forecast_related_threats(
        self,
        incident: Incident,
        analysis_results: Dict[str, Any] = None,
        time_horizons: List[str] = None
    ) -> Dict[str, Any]:
        """
        Forecast threats related to the current incident
        
        Args:
            incident: The current incident to base predictions on
            analysis_results: Results from incident analysis
            time_horizons: List of prediction time frames (e.g., ['1h', '24h', '7d'])
            
        Returns:
            Dictionary containing threat predictions
        """
        if time_horizons is None:
            time_horizons = ['1h', '6h', '24h', '7d', '30d']
        
        logger.info(f"Generating threat predictions for incident {incident.id}")
        
        start_time = datetime.now()
        
        try:
            # Generate cache key
            cache_key = self._generate_prediction_cache_key(incident, analysis_results, time_horizons)
            
            # Check cache first
            if cache_key in self.prediction_cache:
                cached_prediction = self.prediction_cache[cache_key]
                if self._is_prediction_valid(cached_prediction):
                    logger.info(f"Returning cached prediction for incident {incident.id}")
                    return cached_prediction
            
            # Perform parallel prediction analysis with error handling
            try:
                async with asyncio.TaskGroup() as tg:
                    # Historical pattern analysis
                    pattern_task = tg.create_task(
                        self._safe_analyze_historical_patterns(incident, analysis_results)
                    )
                    
                    # Machine learning predictions
                    ml_task = tg.create_task(
                        self._safe_ml_threat_prediction(incident, analysis_results, time_horizons)
                    )
                    
                    # Threat intelligence correlation
                    intel_task = tg.create_task(
                        self._safe_correlate_threat_intelligence(incident, analysis_results)
                    )
                    
                    # Attack progression modeling
                    progression_task = tg.create_task(
                        self._safe_model_attack_progression(incident, analysis_results)
                    )
                    
                    # Environmental risk assessment
                    risk_task = tg.create_task(
                        self._safe_assess_environmental_risks(incident, analysis_results)
                    )
            except* Exception as eg:
                # Handle TaskGroup exceptions gracefully
                logger.warning(f"Some prediction tasks failed for incident {incident.id}: {eg}")
                # Use default safe results via explicit Futures (safer than poking private Task internals)
                loop = asyncio.get_running_loop()

                pattern_task = loop.create_future()
                pattern_task.set_result({'patterns': [], 'confidence': 0.3})

                ml_task = loop.create_future()
                ml_task.set_result({'predictions': [], 'confidence': 0.3})

                intel_task = loop.create_future()
                intel_task.set_result({'correlations': [], 'confidence': 0.3})

                progression_task = loop.create_future()
                progression_task.set_result({'progression': [], 'confidence': 0.3})

                risk_task = loop.create_future()
                risk_task.set_result({'risks': [], 'confidence': 0.3})
            
            # Compile prediction results
            prediction_results = {
                'prediction_id': f"pred_{incident.id}_{int(start_time.timestamp())}",
                'incident_id': incident.id,
                'prediction_timestamp': start_time.isoformat(),
                'time_horizons_analyzed': time_horizons,
                'historical_patterns': pattern_task.result(),
                'ml_predictions': ml_task.result(),
                'threat_intelligence_correlation': intel_task.result(),
                'attack_progression_model': progression_task.result(),
                'environmental_risks': risk_task.result(),
                'consolidated_predictions': [],
                'overall_risk_score': 0.0,
                'confidence_metrics': {},
                'recommended_actions': []
            }
            
            # Consolidate predictions across different analysis methods
            consolidated_predictions = self._consolidate_predictions(prediction_results)
            prediction_results['consolidated_predictions'] = consolidated_predictions
            
            # Calculate overall risk scores
            overall_risk = self._calculate_overall_risk_score(prediction_results)
            prediction_results['overall_risk_score'] = overall_risk
            
            # Generate confidence metrics
            confidence_metrics = self._calculate_confidence_metrics(prediction_results)
            prediction_results['confidence_metrics'] = confidence_metrics
            
            # Generate recommended preventive actions
            recommended_actions = self._generate_preventive_recommendations(
                incident, prediction_results, analysis_results
            )
            prediction_results['recommended_actions'] = recommended_actions
            
            # Add execution metadata
            end_time = datetime.now()
            prediction_results['execution_time_seconds'] = (end_time - start_time).total_seconds()
            prediction_results['models_used'] = list(self.prediction_models.keys())
            prediction_results['prediction_accuracy_estimate'] = self._estimate_prediction_accuracy(prediction_results)
            
            # Cache the results
            self.prediction_cache[cache_key] = prediction_results
            
            logger.info(f"Threat prediction completed for incident {incident.id}. "
                       f"Overall risk score: {overall_risk:.3f}, "
                       f"Predictions generated: {len(consolidated_predictions)}")
            
            return prediction_results
            
        except Exception as e:
            logger.error(f"Error generating threat predictions for incident {incident.id}: {str(e)}")
            return {
                'prediction_id': f"pred_error_{incident.id}_{int(start_time.timestamp())}",
                'incident_id': incident.id,
                'error': str(e),
                'prediction_timestamp': start_time.isoformat(),
                'status': 'failed'
            }
    
    # Safe wrapper functions for TaskGroup error handling
    async def _safe_analyze_historical_patterns(self, incident, analysis_results):
        """Safe wrapper for historical pattern analysis"""
        try:
            return await self._analyze_historical_patterns(incident, analysis_results)
        except Exception as e:
            logger.warning(f"Historical pattern analysis failed: {e}")
            return {'patterns': [], 'confidence': 0.3, 'error': str(e)}

    async def _safe_ml_threat_prediction(self, incident, analysis_results, time_horizons):
        """Safe wrapper for ML threat prediction"""
        try:
            return await self._ml_threat_prediction(incident, analysis_results, time_horizons)
        except Exception as e:
            logger.warning(f"ML threat prediction failed: {e}")
            return {'predictions': [], 'confidence': 0.3, 'error': str(e)}

    async def _safe_correlate_threat_intelligence(self, incident, analysis_results):
        """Safe wrapper for threat intelligence correlation"""
        try:
            return await self._correlate_threat_intelligence(incident, analysis_results)
        except Exception as e:
            logger.warning(f"Threat intelligence correlation failed: {e}")
            return {'correlations': [], 'confidence': 0.3, 'error': str(e)}

    async def _safe_model_attack_progression(self, incident, analysis_results):
        """Safe wrapper for attack progression modeling"""
        try:
            return await self._model_attack_progression(incident, analysis_results)
        except Exception as e:
            logger.warning(f"Attack progression modeling failed: {e}")
            return {'progression': [], 'confidence': 0.3, 'error': str(e)}

    async def _safe_assess_environmental_risks(self, incident, analysis_results):
        """Safe wrapper for environmental risk assessment"""
        try:
            return await self._assess_environmental_risks(incident, analysis_results)
        except Exception as e:
            logger.warning(f"Environmental risk assessment failed: {e}")
            return {'risks': [], 'confidence': 0.3, 'error': str(e)}

    async def _analyze_historical_patterns(
        self,
        incident: Incident,
        analysis_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Analyze historical attack patterns related to current incident"""
        await asyncio.sleep(0.1)  # Simulate analysis time
        
        historical_analysis = {
            'similar_incidents_found': 0,
            'pattern_matches': [],
            'temporal_correlations': {},
            'attack_chains': [],
            'seasonal_trends': {},
            'recurrence_probability': 0.0
        }
        
        # Simulate finding similar historical incidents
        incident_type_mapping = {
            IncidentType.MALWARE: {
                'similar_count': 15,
                'common_patterns': ['email_delivery', 'persistence_mechanism', 'data_collection'],
                'average_recurrence_days': 45
            },
            IncidentType.DATA_BREACH: {
                'similar_count': 8,
                'common_patterns': ['privilege_escalation', 'lateral_movement', 'data_exfiltration'],
                'average_recurrence_days': 90
            },
            IncidentType.NETWORK_ATTACK: {
                'similar_count': 18,
                'common_patterns': ['reconnaissance', 'exploitation', 'persistence'],
                'average_recurrence_days': 75
            },
        }
        
        incident_data = incident_type_mapping.get(incident.incident_type, {
            'similar_count': 5,
            'common_patterns': ['unknown_pattern'],
            'average_recurrence_days': 60
        })
        
        historical_analysis['similar_incidents_found'] = incident_data['similar_count']
        historical_analysis['pattern_matches'] = incident_data['common_patterns']
        
        # Temporal correlation analysis
        historical_analysis['temporal_correlations'] = {
            'time_of_day_correlation': 'high_nighttime_activity',
            'day_of_week_correlation': 'weekend_preference',
            'monthly_pattern': 'end_of_quarter_spike',
            'seasonal_pattern': 'winter_increase'
        }
        
        # Attack chain analysis
        attack_chains = []
        if incident.incident_type in [IncidentType.MALWARE, IncidentType.NETWORK_ATTACK]:
            attack_chains.append({
                'chain_id': 'advanced_persistent_threat',
                'probability': 0.75,
                'next_stages': ['lateral_movement', 'privilege_escalation', 'data_collection'],
                'timeline': '2-14 days'
            })

        # If event data indicates phishing via model tags, add a phishing scenario
        if 'phishing' in (incident.description or '').lower():
            attack_chains.append({
                'chain_id': 'credential_harvesting_campaign',
                'probability': 0.68,
                'next_stages': ['account_takeover', 'business_email_compromise', 'financial_fraud'],
                'timeline': '1-7 days'
            })

        historical_analysis['attack_chains'] = attack_chains
        
        # Seasonal trends
        historical_analysis['seasonal_trends'] = {
            'current_season_risk': 'elevated',
            'peak_activity_months': ['November', 'December', 'January'],
            'trend_direction': 'increasing',
            'year_over_year_change': '+15%'
        }
        
        # Calculate recurrence probability
        base_recurrence = 1.0 / incident_data['average_recurrence_days']
        severity_multiplier = {
            IncidentSeverity.LOW: 0.8,
            IncidentSeverity.MEDIUM: 1.0,
            IncidentSeverity.HIGH: 1.3,
            IncidentSeverity.CRITICAL: 1.6
        }.get(incident.severity, 1.0)
        
        historical_analysis['recurrence_probability'] = min(0.95, base_recurrence * severity_multiplier)
        
        return historical_analysis
    
    async def _ml_threat_prediction(
        self,
        incident: Incident,
        analysis_results: Dict[str, Any],
        time_horizons: List[str]
    ) -> Dict[str, Any]:
        """Generate ML-based threat predictions"""
        await asyncio.sleep(0.2)  # Simulate ML processing time
        
        ml_predictions = {
            'model_predictions': {},
            'ensemble_prediction': {},
            'feature_importance': {},
            'prediction_intervals': {},
            'model_confidence_scores': {}
        }
        
        # Generate predictions from each model
        for model_name, model_info in self.prediction_models.items():
            model_prediction = await self._run_individual_model(
                model_name, model_info, incident, analysis_results, time_horizons
            )
            ml_predictions['model_predictions'][model_name] = model_prediction
            ml_predictions['model_confidence_scores'][model_name] = model_info['accuracy']
        
        # Generate ensemble prediction
        ensemble_prediction = self._generate_ensemble_prediction(
            ml_predictions['model_predictions'], time_horizons
        )
        ml_predictions['ensemble_prediction'] = ensemble_prediction
        
        # Feature importance analysis
        ml_predictions['feature_importance'] = {
            'incident_severity': 0.25,
            'attack_vector_complexity': 0.20,
            'historical_patterns': 0.18,
            'threat_intelligence_signals': 0.15,
            'environmental_factors': 0.12,
            'temporal_characteristics': 0.10
        }
        
        # Prediction intervals (confidence bounds)
        ml_predictions['prediction_intervals'] = {
            horizon: {
                'lower_bound': max(0.0, ensemble_prediction.get(horizon, {}).get('probability', 0.5) - 0.15),
                'upper_bound': min(1.0, ensemble_prediction.get(horizon, {}).get('probability', 0.5) + 0.15),
                'confidence_level': 0.95
            }
            for horizon in time_horizons
        }
        
        return ml_predictions
    
    async def _run_individual_model(
        self,
        model_name: str,
        model_info: Dict[str, Any],
        incident: Incident,
        analysis_results: Dict[str, Any],
        time_horizons: List[str]
    ) -> Dict[str, Any]:
        """Run prediction on an individual ML model"""
        await asyncio.sleep(0.02)  # Simulate model execution time
        
        # Simulate model-specific predictions
        base_probability = self._calculate_base_probability(incident, analysis_results)
        
        # Model-specific adjustments
        model_adjustments = {
            'temporal_pattern_model': {
                '1h': 0.1, '6h': 0.2, '24h': 0.3, '7d': 0.4, '30d': 0.5
            },
            'attack_vector_model': {
                '1h': 0.05, '6h': 0.15, '24h': 0.35, '7d': 0.5, '30d': 0.6
            },
            'threat_actor_model': {
                '1h': 0.02, '6h': 0.1, '24h': 0.25, '7d': 0.45, '30d': 0.65
            },
            'vulnerability_exploitation_model': {
                '1h': 0.15, '6h': 0.25, '24h': 0.4, '7d': 0.55, '30d': 0.7
            },
            'lateral_movement_model': {
                '1h': 0.03, '6h': 0.12, '24h': 0.28, '7d': 0.48, '30d': 0.68
            }
        }
        
        adjustments = model_adjustments.get(model_name, {
            '1h': 0.1, '6h': 0.2, '24h': 0.3, '7d': 0.4, '30d': 0.5
        })
        
        predictions = {}
        for horizon in time_horizons:
            adjustment = adjustments.get(horizon, 0.3)
            probability = min(0.95, base_probability + adjustment)
            
            predictions[horizon] = {
                'probability': probability,
                'confidence': model_info['accuracy'],
                'predicted_threats': self._generate_threat_predictions_for_horizon(incident, horizon),
                'risk_factors': self._identify_risk_factors(incident, horizon)
            }
        
        return {
            'model_type': model_info['type'],
            'model_accuracy': model_info['accuracy'],
            'predictions_by_horizon': predictions,
            'last_training_date': model_info['last_updated'].isoformat()
        }
    
    async def _correlate_threat_intelligence(
        self,
        incident: Incident,
        analysis_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Correlate with threat intelligence feeds"""
        await asyncio.sleep(0.08)
        
        intel_correlation = {
            'feed_correlations': {},
            'actor_attribution': {},
            'campaign_indicators': [],
            'emerging_threats': [],
            'geographic_indicators': {},
            'correlation_confidence': 0.0
        }
        
        # Correlate with each threat intelligence feed
        total_correlation_score = 0.0
        feed_count = 0
        
        for feed_name, feed_info in self.threat_intelligence_feeds.items():
            feed_correlation = await self._correlate_with_feed(
                feed_name, feed_info, incident, analysis_results
            )
            intel_correlation['feed_correlations'][feed_name] = feed_correlation
            total_correlation_score += feed_correlation['correlation_score']
            feed_count += 1
        
        # Calculate overall correlation confidence
        intel_correlation['correlation_confidence'] = total_correlation_score / feed_count if feed_count > 0 else 0.0
        
        # Threat actor attribution
        intel_correlation['actor_attribution'] = {
            'suspected_actors': ['APT29', 'FIN7', 'Lazarus Group'],
            'attribution_confidence': 0.65,
            'geographic_origin': ['Russia', 'North Korea', 'China'],
            'motivation': ['financial', 'espionage', 'disruption']
        }
        
        # Campaign indicators
        intel_correlation['campaign_indicators'] = [
            {
                'campaign_name': 'Operation ShadowNet',
                'match_probability': 0.78,
                'shared_indicators': ['C2_infrastructure', 'malware_family', 'attack_timing']
            },
            {
                'campaign_name': 'DarkHalo Campaign',
                'match_probability': 0.42,
                'shared_indicators': ['target_selection', 'initial_access_method']
            }
        ]
        
        # Emerging threats
        intel_correlation['emerging_threats'] = [
            {
                'threat_name': 'AI-Enhanced Phishing',
                'emergence_probability': 0.85,
                'time_frame': '30 days',
                'impact_potential': 'high'
            },
            {
                'threat_name': 'Supply Chain Compromise',
                'emergence_probability': 0.72,
                'time_frame': '60 days',
                'impact_potential': 'critical'
            }
        ]
        
        # Geographic risk indicators
        intel_correlation['geographic_indicators'] = {
            'high_risk_regions': ['Eastern Europe', 'Southeast Asia'],
            'attack_source_likelihood': {
                'Russia': 0.35,
                'China': 0.28,
                'North Korea': 0.15,
                'Iran': 0.12,
                'Other': 0.10
            },
            'regional_threat_trends': 'increasing_sophistication'
        }
        
        return intel_correlation
    
    async def _correlate_with_feed(
        self,
        feed_name: str,
        feed_info: Dict[str, Any],
        incident: Incident,
        analysis_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Correlate incident with specific threat intelligence feed"""
        await asyncio.sleep(0.01)
        
        # Simulate feed-specific correlation logic
        base_correlation = random.uniform(0.3, 0.8)
        
        # Adjust correlation based on feed reliability
        reliability_factor = feed_info.get('reliability', 0.8)
        adjusted_correlation = base_correlation * reliability_factor
        
        # Feed-specific enhancements
        if feed_name == 'mitre_attack':
            techniques_matched = ['T1566.001', 'T1059.001', 'T1055']
            tactics_matched = ['Initial Access', 'Execution', 'Defense Evasion']
        elif feed_name == 'cve_database':
            techniques_matched = ['CVE-2023-1234', 'CVE-2023-5678']
            tactics_matched = ['Privilege Escalation', 'Remote Code Execution']
        else:
            techniques_matched = ['generic_indicator_1', 'generic_indicator_2']
            tactics_matched = ['reconnaissance', 'initial_access']
        
        return {
            'correlation_score': adjusted_correlation,
            'feed_reliability': reliability_factor,
            'matched_indicators': len(techniques_matched),
            'techniques_matched': techniques_matched,
            'tactics_matched': tactics_matched,
            'last_feed_update': feed_info.get('last_update', datetime.now()).isoformat(),
            'relevance_score': min(1.0, adjusted_correlation + 0.1)
        }
    
    async def _model_attack_progression(
        self,
        incident: Incident,
        analysis_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Model potential attack progression scenarios"""
        await asyncio.sleep(0.06)
        
        progression_model = {
            'attack_scenarios': [],
            'progression_probability': {},
            'critical_decision_points': [],
            'defensive_opportunities': [],
            'escalation_triggers': []
        }
        
        # Generate attack scenarios based on incident type
        if incident.incident_type == IncidentType.MALWARE:
            scenarios = [
                {
                    'scenario_name': 'Ransomware Deployment',
                    'probability': 0.65,
                    'stages': [
                        {'stage': 'reconnaissance', 'time_estimate': '2-6 hours'},
                        {'stage': 'lateral_movement', 'time_estimate': '6-24 hours'},
                        {'stage': 'data_encryption', 'time_estimate': '1-4 hours'},
                        {'stage': 'ransom_demand', 'time_estimate': 'immediate'}
                    ]
                },
                {
                    'scenario_name': 'Data Exfiltration',
                    'probability': 0.45,
                    'stages': [
                        {'stage': 'privilege_escalation', 'time_estimate': '1-8 hours'},
                        {'stage': 'data_discovery', 'time_estimate': '4-12 hours'},
                        {'stage': 'data_staging', 'time_estimate': '2-6 hours'},
                        {'stage': 'exfiltration', 'time_estimate': '1-3 hours'}
                    ]
                }
            ]
    elif 'phishing' in (incident.description or '').lower():
        scenarios = [
            {
                'scenario_name': 'Credential Harvesting Campaign',
                'probability': 0.78,
                'stages': [
                    {'stage': 'credential_collection', 'time_estimate': '1-24 hours'},
                    {'stage': 'account_validation', 'time_estimate': '1-6 hours'},
                    {'stage': 'account_takeover', 'time_estimate': '2-12 hours'},
                    {'stage': 'lateral_compromise', 'time_estimate': '6-48 hours'}
                ]
            }
        ]
    else:
        scenarios = [
            {
                'scenario_name': 'Generic Attack Progression',
                'probability': 0.55,
                'stages': [
                    {'stage': 'initial_compromise', 'time_estimate': '1-4 hours'},
                    {'stage': 'persistence', 'time_estimate': '2-8 hours'},
                    {'stage': 'discovery', 'time_estimate': '4-24 hours'},
                    {'stage': 'impact', 'time_estimate': '1-12 hours'}
                ]
            }
        ]
        
        progression_model['attack_scenarios'] = scenarios
        
        # Progression probabilities by time horizon
        progression_model['progression_probability'] = {
            '1h': 0.15,
            '6h': 0.35,
            '24h': 0.65,
            '7d': 0.85,
            '30d': 0.95
        }
        
        # Critical decision points
        progression_model['critical_decision_points'] = [
            {
                'decision_point': 'privilege_escalation_attempt',
                'time_window': '2-8 hours',
                'impact_if_successful': 'high',
                'detection_probability': 0.75
            },
            {
                'decision_point': 'lateral_movement_initiation',
                'time_window': '4-24 hours',
                'impact_if_successful': 'critical',
                'detection_probability': 0.68
            }
        ]
        
        # Defensive opportunities
        progression_model['defensive_opportunities'] = [
            {
                'opportunity': 'network_segmentation_enforcement',
                'effectiveness': 0.85,
                'implementation_time': '30 minutes',
                'resource_requirement': 'medium'
            },
            {
                'opportunity': 'credential_rotation',
                'effectiveness': 0.78,
                'implementation_time': '2 hours',
                'resource_requirement': 'high'
            }
        ]
        
        # Escalation triggers
        progression_model['escalation_triggers'] = [
            {
                'trigger': 'multiple_system_compromise',
                'probability': 0.45,
                'severity_increase': 'high_to_critical'
            },
            {
                'trigger': 'sensitive_data_access',
                'probability': 0.32,
                'severity_increase': 'medium_to_high'
            }
        ]
        
        return progression_model
    
    async def _assess_environmental_risks(
        self,
        incident: Incident,
        analysis_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Assess environmental risk factors"""
        await asyncio.sleep(0.04)
        
        environmental_risks = {
            'infrastructure_vulnerabilities': {},
            'organizational_risk_factors': {},
            'external_threat_landscape': {},
            'compliance_implications': {},
            'business_continuity_risks': {}
        }
        
        # Infrastructure vulnerabilities
        environmental_risks['infrastructure_vulnerabilities'] = {
            'unpatched_systems_count': 25,
            'legacy_system_exposure': 'high',
            'network_segmentation_score': 0.65,
            'endpoint_protection_coverage': 0.88,
            'backup_system_status': 'operational',
            'critical_asset_exposure': 'medium'
        }
        
        # Organizational risk factors
        environmental_risks['organizational_risk_factors'] = {
            'security_awareness_level': 'medium',
            'incident_response_maturity': 'developing',
            'staff_security_training_current': 0.75,
            'privileged_access_management': 'partial',
            'third_party_risk_exposure': 'high',
            'change_management_process': 'informal'
        }
        
        # External threat landscape
        environmental_risks['external_threat_landscape'] = {
            'industry_targeting_trend': 'increasing',
            'geographic_threat_level': 'elevated',
            'threat_actor_activity': 'high',
            'zero_day_market_activity': 'moderate',
            'supply_chain_risk_level': 'high',
            'geopolitical_risk_factors': ['trade_tensions', 'cyber_warfare']
        }
        
        # Compliance implications
        environmental_risks['compliance_implications'] = {
            'regulatory_frameworks': ['GDPR', 'SOX', 'HIPAA'],
            'breach_notification_requirements': True,
            'audit_schedule': 'quarterly',
            'compliance_gap_analysis': 'overdue',
            'regulatory_penalty_risk': 'medium',
            'certification_at_risk': ['ISO27001', 'SOC2']
        }
        
        # Business continuity risks
        environmental_risks['business_continuity_risks'] = {
            'critical_process_dependency': 'high',
            'revenue_impact_potential': 'significant',
            'customer_impact_risk': 'moderate',
            'reputation_damage_potential': 'high',
            'recovery_time_objective': '4 hours',
            'recovery_point_objective': '1 hour'
        }
        
        return environmental_risks
    
    def _consolidate_predictions(self, prediction_results: Dict[str, Any]) -> List[ThreatPrediction]:
        """Consolidate predictions from different analysis methods"""
        consolidated = []
        
        # Extract predictions from ML models
        ml_predictions = prediction_results.get('ml_predictions', {})
        ensemble_prediction = ml_predictions.get('ensemble_prediction', {})
        
        # Extract threat intelligence correlations
        intel_correlation = prediction_results.get('threat_intelligence_correlation', {})
        emerging_threats = intel_correlation.get('emerging_threats', [])
        
        # Extract attack progression scenarios
        progression_model = prediction_results.get('attack_progression_model', {})
        attack_scenarios = progression_model.get('attack_scenarios', [])
        
        # Generate consolidated threat predictions
        prediction_id_counter = 1
        
        # Predictions from ensemble ML model
        for horizon, prediction_data in ensemble_prediction.items():
            threat_prediction = ThreatPrediction(
                threat_id=f"ml_pred_{prediction_id_counter}",
                threat_category=self._map_incident_to_threat_category(prediction_results['incident_id']),
                predicted_severity=self._predict_severity_from_probability(prediction_data.get('probability', 0.5)),
                probability=prediction_data.get('probability', 0.5),
                confidence=self._map_probability_to_confidence(prediction_data.get('probability', 0.5)),
                time_frame=horizon,
                target_assets=prediction_data.get('target_assets', ['unknown']),
                attack_vectors=prediction_data.get('attack_vectors', ['unknown']),
                indicators=prediction_data.get('indicators', []),
                mitigation_suggestions=prediction_data.get('mitigations', []),
                related_incidents=[prediction_results['incident_id']],
                prediction_timestamp=datetime.now(),
                expiration_time=datetime.now() + self._horizon_to_timedelta(horizon),
                risk_factors=prediction_data.get('risk_factors', {}),
                threat_actor_profile=intel_correlation.get('actor_attribution', {})
            )
            consolidated.append(threat_prediction)
            prediction_id_counter += 1
        
        # Predictions from emerging threats
        for emerging_threat in emerging_threats:
            threat_prediction = ThreatPrediction(
                threat_id=f"emerging_threat_{prediction_id_counter}",
                threat_category=self._map_threat_name_to_category(emerging_threat.get('threat_name', '')),
                predicted_severity=IncidentSeverity.HIGH,  # Emerging threats are typically high severity
                probability=emerging_threat.get('emergence_probability', 0.5),
                confidence=PredictionConfidence.MEDIUM,
                time_frame=emerging_threat.get('time_frame', '30d'),
                target_assets=['infrastructure', 'data', 'users'],
                attack_vectors=['unknown'],
                indicators=['emerging_technique'],
                mitigation_suggestions=['monitor_threat_landscape', 'update_defenses'],
                related_incidents=[prediction_results['incident_id']],
                prediction_timestamp=datetime.now(),
                expiration_time=datetime.now() + timedelta(days=30),
                risk_factors={'emergence_trend': 1.0},
                threat_actor_profile={'sophistication': 'high', 'resources': 'extensive'}
            )
            consolidated.append(threat_prediction)
            prediction_id_counter += 1
        
        # Predictions from attack scenarios
        for scenario in attack_scenarios:
            threat_prediction = ThreatPrediction(
                threat_id=f"scenario_{prediction_id_counter}",
                threat_category=self._map_scenario_to_threat_category(scenario.get('scenario_name', '')),
                predicted_severity=IncidentSeverity.HIGH,
                probability=scenario.get('probability', 0.5),
                confidence=PredictionConfidence.HIGH,
                time_frame='7d',  # Most attack scenarios unfold within a week
                target_assets=['systems', 'data', 'network'],
                attack_vectors=['progression_based'],
                indicators=['attack_progression'],
                mitigation_suggestions=['implement_detection', 'strengthen_controls'],
                related_incidents=[prediction_results['incident_id']],
                prediction_timestamp=datetime.now(),
                expiration_time=datetime.now() + timedelta(days=7),
                risk_factors={'progression_probability': scenario.get('probability', 0.5)},
                threat_actor_profile={'motivation': 'varies', 'capability': 'moderate_to_high'}
            )
            consolidated.append(threat_prediction)
            prediction_id_counter += 1
        
        # Sort by probability and time frame
        consolidated.sort(key=lambda x: (x.probability, self._time_frame_to_hours(x.time_frame)), reverse=True)
        
        return consolidated
    
    def _calculate_overall_risk_score(self, prediction_results: Dict[str, Any]) -> float:
        """Calculate overall risk score from all predictions"""
        risk_factors = []
        
        # ML prediction risk
        ml_predictions = prediction_results.get('ml_predictions', {})
        ensemble_prediction = ml_predictions.get('ensemble_prediction', {})
        if ensemble_prediction:
            avg_ml_probability = sum(
                pred.get('probability', 0.0) for pred in ensemble_prediction.values()
            ) / len(ensemble_prediction)
            risk_factors.append(avg_ml_probability * 0.3)
        
        # Threat intelligence risk
        intel_correlation = prediction_results.get('threat_intelligence_correlation', {})
        correlation_confidence = intel_correlation.get('correlation_confidence', 0.0)
        risk_factors.append(correlation_confidence * 0.25)
        
        # Historical pattern risk
        historical_patterns = prediction_results.get('historical_patterns', {})
        recurrence_probability = historical_patterns.get('recurrence_probability', 0.0)
        risk_factors.append(recurrence_probability * 0.2)
        
        # Attack progression risk
        progression_model = prediction_results.get('attack_progression_model', {})
        progression_probabilities = progression_model.get('progression_probability', {})
        if progression_probabilities:
            avg_progression_risk = sum(progression_probabilities.values()) / len(progression_probabilities)
            risk_factors.append(avg_progression_risk * 0.15)
        
        # Environmental risk
        environmental_risks = prediction_results.get('environmental_risks', {})
        # Simplified environmental risk calculation
        env_risk_score = 0.6  # Moderate environmental risk baseline
        risk_factors.append(env_risk_score * 0.1)
        
        # Calculate weighted average
        overall_risk = sum(risk_factors) if risk_factors else 0.5
        
        return min(1.0, max(0.0, overall_risk))
    
    def _calculate_confidence_metrics(self, prediction_results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate confidence metrics for the predictions"""
        confidence_metrics = {
            'overall_confidence': 0.0,
            'data_quality_score': 0.0,
            'model_agreement_score': 0.0,
            'temporal_consistency_score': 0.0,
            'uncertainty_factors': []
        }
        
        # Calculate overall confidence from model accuracies
        ml_predictions = prediction_results.get('ml_predictions', {})
        model_confidence_scores = ml_predictions.get('model_confidence_scores', {})
        if model_confidence_scores:
            confidence_metrics['overall_confidence'] = sum(model_confidence_scores.values()) / len(model_confidence_scores)
        
        # Data quality score based on recency and completeness
        threat_intel = prediction_results.get('threat_intelligence_correlation', {})
        feed_correlations = threat_intel.get('feed_correlations', {})
        if feed_correlations:
            relevance_scores = [feed.get('relevance_score', 0.5) for feed in feed_correlations.values()]
            confidence_metrics['data_quality_score'] = sum(relevance_scores) / len(relevance_scores)
        
        # Model agreement score
        model_predictions = ml_predictions.get('model_predictions', {})
        if len(model_predictions) > 1:
            # Calculate variance in predictions as agreement metric
            all_probabilities = []
            for model_pred in model_predictions.values():
                for horizon_pred in model_pred.get('predictions_by_horizon', {}).values():
                    all_probabilities.append(horizon_pred.get('probability', 0.5))
            
            if all_probabilities:
                variance = sum((p - sum(all_probabilities) / len(all_probabilities))**2 for p in all_probabilities) / len(all_probabilities)
                agreement_score = max(0.0, 1.0 - variance)  # Lower variance = higher agreement
                confidence_metrics['model_agreement_score'] = agreement_score
        
        # Temporal consistency score
        confidence_metrics['temporal_consistency_score'] = 0.75  # Simulated value
        
        # Uncertainty factors
        uncertainty_factors = []
        if confidence_metrics['data_quality_score'] < 0.7:
            uncertainty_factors.append('low_data_quality')
        if confidence_metrics['model_agreement_score'] < 0.6:
            uncertainty_factors.append('model_disagreement')
        if len(model_predictions) < 3:
            uncertainty_factors.append('insufficient_models')
        
        confidence_metrics['uncertainty_factors'] = uncertainty_factors
        
        return confidence_metrics
    
    def _generate_preventive_recommendations(
        self,
        incident: Incident,
        prediction_results: Dict[str, Any],
        analysis_results: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate preventive action recommendations"""
        recommendations = []
        
        # Base recommendations on consolidated predictions
        consolidated_predictions = prediction_results.get('consolidated_predictions', [])
        
        for prediction in consolidated_predictions[:5]:  # Top 5 predictions
            if prediction.probability > 0.6:  # High probability threats
                recommendations.extend([
                    {
                        'action': f'implement_detection_for_{prediction.threat_category.value}',
                        'priority': 'high' if prediction.probability > 0.8 else 'medium',
                        'timeframe': prediction.time_frame,
                        'threat_addressed': prediction.threat_id,
                        'expected_effectiveness': min(0.9, prediction.probability * 1.2)
                    },
                    {
                        'action': f'strengthen_controls_against_{prediction.threat_category.value}',
                        'priority': 'medium',
                        'timeframe': prediction.time_frame,
                        'threat_addressed': prediction.threat_id,
                        'expected_effectiveness': min(0.85, prediction.probability * 1.1)
                    }
                ])
        
        # Environmental risk-based recommendations
        environmental_risks = prediction_results.get('environmental_risks', {})
        infrastructure_vulns = environmental_risks.get('infrastructure_vulnerabilities', {})
        
        if infrastructure_vulns.get('unpatched_systems_count', 0) > 20:
            recommendations.append({
                'action': 'prioritize_patch_management',
                'priority': 'high',
                'timeframe': '48h',
                'threat_addressed': 'vulnerability_exploitation',
                'expected_effectiveness': 0.85
            })
        
        if infrastructure_vulns.get('network_segmentation_score', 1.0) < 0.7:
            recommendations.append({
                'action': 'improve_network_segmentation',
                'priority': 'medium',
                'timeframe': '7d',
                'threat_addressed': 'lateral_movement',
                'expected_effectiveness': 0.75
            })
        
        # Threat intelligence-based recommendations
        intel_correlation = prediction_results.get('threat_intelligence_correlation', {})
        emerging_threats = intel_correlation.get('emerging_threats', [])
        
        for threat in emerging_threats:
            if threat.get('emergence_probability', 0) > 0.7:
                recommendations.append({
                    'action': f'prepare_defenses_for_{threat.get("threat_name", "").lower().replace(" ", "_")}',
                    'priority': 'medium',
                    'timeframe': threat.get('time_frame', '30d'),
                    'threat_addressed': threat.get('threat_name', 'unknown'),
                    'expected_effectiveness': 0.7
                })
        
        # Remove duplicates and sort by priority
        unique_recommendations = []
        seen_actions = set()
        
        for rec in recommendations:
            if rec['action'] not in seen_actions:
                unique_recommendations.append(rec)
                seen_actions.add(rec['action'])
        
        # Sort by priority and effectiveness
        priority_order = {'high': 3, 'medium': 2, 'low': 1}
        unique_recommendations.sort(
            key=lambda x: (priority_order.get(x['priority'], 0), x['expected_effectiveness']),
            reverse=True
        )
        
        return unique_recommendations[:10]  # Return top 10 recommendations
    
    # Helper methods
    def _generate_prediction_cache_key(
        self,
        incident: Incident,
        analysis_results: Dict[str, Any],
        time_horizons: List[str]
    ) -> str:
        """Generate cache key for predictions"""
        key_components = [
            incident.id,
            incident.incident_type.value,
            incident.severity.value,
            str(sorted(time_horizons))
        ]
        return "_".join(key_components)
    
    def _is_prediction_valid(self, prediction: Dict[str, Any]) -> bool:
        """Check if cached prediction is still valid"""
        prediction_time = datetime.fromisoformat(prediction['prediction_timestamp'])
        cache_duration = timedelta(hours=1)  # Predictions valid for 1 hour
        return datetime.now() - prediction_time < cache_duration
    
    def _calculate_base_probability(self, incident: Incident, analysis_results: Dict[str, Any]) -> float:
        """Calculate base probability for threat predictions"""
        # Start with severity-based probability
        severity_probabilities = {
            IncidentSeverity.LOW: 0.2,
            IncidentSeverity.MEDIUM: 0.4,
            IncidentSeverity.HIGH: 0.6,
            IncidentSeverity.CRITICAL: 0.8
        }
        
        base_prob = severity_probabilities.get(incident.severity, 0.4)
        
        # Adjust based on analysis results
        risk_assessment = analysis_results.get('risk_assessment', {})
        risk_score = risk_assessment.get('risk_score', 0.5)
        
        # Combine severity and risk score
        adjusted_prob = (base_prob * 0.6) + (risk_score * 0.4)
        
        return min(0.9, max(0.1, adjusted_prob))
    
    def _generate_threat_predictions_for_horizon(self, incident: Incident, horizon: str) -> List[str]:
        """Generate specific threat predictions for time horizon"""
        threat_mapping = {
            IncidentType.MALWARE: ['ransomware_deployment', 'data_exfiltration', 'lateral_movement'],
            IncidentType.DATA_BREACH: ['data_monetization', 'identity_theft', 'regulatory_scrutiny'],
            IncidentType.NETWORK_ATTACK: ['ddos_amplification', 'ransom_demands', 'reputation_damage'],
            IncidentType.ZERO_DAY: ['exploit_development', 'targeted_attack', 'escalation'],
            IncidentType.SYSTEM_FAILURE: ['service_disruption', 'performance_degradation', 'recovery_procedures']
        }
        
        return threat_mapping.get(incident.incident_type, ['unknown_threat'])
    
    def _identify_risk_factors(self, incident: Incident, horizon: str) -> Dict[str, float]:
        """Identify risk factors for specific time horizon"""
        base_factors = {
            'attack_sophistication': 0.6,
            'target_value': 0.7,
            'defense_maturity': 0.5,
            'threat_actor_capability': 0.6
        }
        
        # Adjust factors based on time horizon
        time_multipliers = {
            '1h': 0.8,
            '6h': 0.9,
            '24h': 1.0,
            '7d': 1.1,
            '30d': 1.2
        }
        
        multiplier = time_multipliers.get(horizon, 1.0)
        return {factor: min(1.0, value * multiplier) for factor, value in base_factors.items()}
    
    def _generate_ensemble_prediction(
        self,
        model_predictions: Dict[str, Any],
        time_horizons: List[str]
    ) -> Dict[str, Any]:
        """Generate ensemble prediction from individual model predictions"""
        ensemble = {}
        
        for horizon in time_horizons:
            horizon_predictions = []
            
            for model_name, model_prediction in model_predictions.items():
                horizon_data = model_prediction.get('predictions_by_horizon', {}).get(horizon, {})
                if horizon_data:
                    probability = horizon_data.get('probability', 0.5)
                    confidence = horizon_data.get('confidence', 0.5)
                    # Weight by model confidence
                    weighted_probability = probability * confidence
                    horizon_predictions.append(weighted_probability)
            
            if horizon_predictions:
                # Calculate weighted average
                ensemble_probability = sum(horizon_predictions) / len(horizon_predictions)
                
                ensemble[horizon] = {
                    'probability': ensemble_probability,
                    'confidence': self._calculate_ensemble_confidence(model_predictions, horizon),
                    'target_assets': ['critical_systems', 'sensitive_data', 'user_accounts'],
                    'attack_vectors': ['network_based', 'email_based', 'endpoint_based'],
                    'indicators': ['pattern_correlation', 'behavior_anomaly', 'threat_intelligence'],
                    'mitigations': ['enhance_monitoring', 'strengthen_controls', 'user_awareness'],
                    'risk_factors': self._aggregate_risk_factors(model_predictions, horizon)
                }
        
        return ensemble
    
    def _calculate_ensemble_confidence(self, model_predictions: Dict[str, Any], horizon: str) -> float:
        """Calculate confidence for ensemble prediction"""
        confidences = []
        
        for model_prediction in model_predictions.values():
            horizon_data = model_prediction.get('predictions_by_horizon', {}).get(horizon, {})
            if horizon_data:
                confidences.append(horizon_data.get('confidence', 0.5))
        
        return sum(confidences) / len(confidences) if confidences else 0.5
    
    def _aggregate_risk_factors(self, model_predictions: Dict[str, Any], horizon: str) -> Dict[str, float]:
        """Aggregate risk factors from multiple models"""
        all_risk_factors = {}
        
        for model_prediction in model_predictions.values():
            horizon_data = model_prediction.get('predictions_by_horizon', {}).get(horizon, {})
            risk_factors = horizon_data.get('risk_factors', {})
            
            for factor, value in risk_factors.items():
                if factor in all_risk_factors:
                    all_risk_factors[factor] = (all_risk_factors[factor] + value) / 2
                else:
                    all_risk_factors[factor] = value
        
        return all_risk_factors
    
    def _estimate_prediction_accuracy(self, prediction_results: Dict[str, Any]) -> float:
        """Estimate overall prediction accuracy"""
        # Use ensemble model accuracy as baseline
        return self.model_accuracies.get('ensemble_prediction', 0.88)
    
    # Mapping helper methods
    def _map_incident_to_threat_category(self, incident_id: str) -> ThreatCategory:
        """Map incident to threat category (simplified)"""
        return ThreatCategory.MALWARE  # Default mapping
    
    def _map_threat_name_to_category(self, threat_name: str) -> ThreatCategory:
        """Map threat name to category"""
        threat_name_lower = threat_name.lower()
        
        if 'phishing' in threat_name_lower:
            return ThreatCategory.PHISHING
        elif 'ransomware' in threat_name_lower:
            return ThreatCategory.RANSOMWARE
        elif 'ddos' in threat_name_lower:
            return ThreatCategory.DDOS
        elif 'supply chain' in threat_name_lower:
            return ThreatCategory.SUPPLY_CHAIN
        elif 'apt' in threat_name_lower or 'advanced' in threat_name_lower:
            return ThreatCategory.APT
        else:
            return ThreatCategory.MALWARE
    
    def _map_scenario_to_threat_category(self, scenario_name: str) -> ThreatCategory:
        """Map attack scenario to threat category"""
        scenario_lower = scenario_name.lower()
        
        if 'ransomware' in scenario_lower:
            return ThreatCategory.RANSOMWARE
        elif 'credential' in scenario_lower or 'phishing' in scenario_lower:
            return ThreatCategory.PHISHING
        elif 'data' in scenario_lower and 'breach' in scenario_lower:
            return ThreatCategory.DATA_BREACH
        else:
            return ThreatCategory.MALWARE
    
    def _predict_severity_from_probability(self, probability: float) -> IncidentSeverity:
        """Predict severity level from probability"""
        if probability >= 0.8:
            return IncidentSeverity.CRITICAL
        elif probability >= 0.6:
            return IncidentSeverity.HIGH
        elif probability >= 0.4:
            return IncidentSeverity.MEDIUM
        else:
            return IncidentSeverity.LOW
    
    def _map_probability_to_confidence(self, probability: float) -> PredictionConfidence:
        """Map probability to confidence level"""
        if probability >= 0.85:
            return PredictionConfidence.VERY_HIGH
        elif probability >= 0.7:
            return PredictionConfidence.HIGH
        elif probability >= 0.5:
            return PredictionConfidence.MEDIUM
        elif probability >= 0.3:
            return PredictionConfidence.LOW
        else:
            return PredictionConfidence.VERY_LOW
    
    def _horizon_to_timedelta(self, horizon: str) -> timedelta:
        """Convert time horizon string to timedelta"""
        if horizon.endswith('h'):
            hours = int(horizon[:-1])
            return timedelta(hours=hours)
        elif horizon.endswith('d'):
            days = int(horizon[:-1])
            return timedelta(days=days)
        else:
            return timedelta(days=1)  # Default
    
    def _time_frame_to_hours(self, time_frame: str) -> int:
        """Convert time frame to hours for sorting"""
        if time_frame.endswith('h'):
            return int(time_frame[:-1])
        elif time_frame.endswith('d'):
            return int(time_frame[:-1]) * 24
        else:
            return 24  # Default

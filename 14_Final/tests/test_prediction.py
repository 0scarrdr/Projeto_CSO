"""
Unit Tests for Prediction Components
Tests threat prediction, forecasting, and machine learning models
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch
from datetime import datetime, timedelta
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from soar.prediction.threat_predictor import ThreatPredictor
from soar.models.incident import Incident, IncidentType, IncidentSeverity, IncidentStatus


@pytest.fixture
def sample_incident():
    """Sample incident for prediction testing"""
    incident = Mock(spec=Incident)
    incident.id = "test-incident-001"
    incident.incident_type = IncidentType.MALWARE
    incident.severity = IncidentSeverity.HIGH
    incident.status = IncidentStatus.DETECTED
    incident.source_ip = "192.168.1.100"
    incident.host_id = "WS-001"
    incident.description = "Malware detected on workstation"
    incident.timestamp = datetime.now()
    incident.attributes = {
        "source_ip": "192.168.1.100",
        "host_id": "WS-001",
        "file_hash": "abc123def456"
    }
    return incident


@pytest.fixture
def historical_incidents():
    """Sample historical incidents for prediction training"""
    incidents = []
    base_time = datetime.now() - timedelta(days=30)

    for i in range(10):
        incident = Mock(spec=Incident)
        incident.id = f"historical-{i}"
        incident.incident_type = IncidentType.MALWARE if i % 2 == 0 else IncidentType.NETWORK_ATTACK
        incident.severity = IncidentSeverity.HIGH if i < 3 else IncidentSeverity.MEDIUM
        incident.source_ip = f"192.168.1.{100 + i}"
        incident.timestamp = base_time + timedelta(days=i)
        incident.resolved = i < 8  # 80% resolution rate
        incidents.append(incident)

    return incidents


class TestThreatPredictor:
    """Test ThreatPredictor functionality"""

    @pytest.fixture
    def threat_predictor(self):
        """Create ThreatPredictor instance"""
        predictor = ThreatPredictor()
        return predictor

    @pytest.mark.asyncio
    async def test_initialization(self, threat_predictor):
        """Test ThreatPredictor initialization"""
        assert threat_predictor.ml_model is not None
        assert threat_predictor.pattern_analyzer is not None
        assert threat_predictor.threat_intelligence is not None

    @pytest.mark.asyncio
    async def test_forecast_related_threats(self, threat_predictor, sample_incident):
        """Test forecasting related threats"""
        result = await threat_predictor.forecast_related_threats(sample_incident)

        assert result["success"] is True
        assert "predicted_threats" in result
        assert "confidence_score" in result
        assert "time_window" in result

        # Should predict related threats for malware incident
        predicted_threats = result["predicted_threats"]
        assert len(predicted_threats) > 0

    @pytest.mark.asyncio
    async def test_predict_attack_progression(self, threat_predictor, sample_incident):
        """Test prediction of attack progression"""
        result = await threat_predictor.forecast_related_threats(sample_incident)

        # Should include attack progression predictions
        assert "attack_progression" in result
        progression = result["attack_progression"]

        # Common progression for malware
        expected_stages = ["initial_compromise", "lateral_movement", "data_exfiltration"]
        for stage in expected_stages:
            assert stage in progression

    @pytest.mark.asyncio
    async def test_risk_trend_analysis(self, threat_predictor, historical_incidents):
        """Test risk trend analysis"""
        # Mock historical data
        with patch.object(threat_predictor, 'get_historical_incidents') as mock_history:
            mock_history.return_value = historical_incidents

            trends = await threat_predictor.analyze_risk_trends()

            assert "trend_direction" in trends
            assert "risk_increase_rate" in trends
            assert "predicted_risk_level" in trends

    @pytest.mark.asyncio
    async def test_machine_learning_predictions(self, threat_predictor, sample_incident):
        """Test machine learning model predictions"""
        # Mock ML model
        with patch('soar.prediction.threat_predictor.MLModel') as mock_ml:
            mock_ml_instance = Mock()
            mock_ml_instance.predict_threat_probability.return_value = 0.75
            mock_ml_instance.predict_attack_type.return_value = "ransomware"
            mock_ml_instance.predict_time_to_compromise.return_value = 3600
            mock_ml.return_value = mock_ml_instance

            result = await threat_predictor.forecast_related_threats(sample_incident)

            # Verify ML model was used
            mock_ml_instance.predict_threat_probability.assert_called_once()
            mock_ml_instance.predict_attack_type.assert_called_once()

            # Verify predictions are incorporated
            assert result["confidence_score"] >= 0.7

    @pytest.mark.asyncio
    async def test_threat_intelligence_enrichment(self, threat_predictor, sample_incident):
        """Test threat intelligence enrichment in predictions"""
        # Mock threat intelligence
        threat_predictor.threat_intelligence = AsyncMock()
        threat_predictor.threat_intelligence.get_related_threats.return_value = [
            {
                "threat_type": "ransomware",
                "confidence": 0.8,
                "indicators": ["file_hash_similar", "c2_server"],
                "campaign": "LockBit_Ransomware"
            }
        ]

        result = await threat_predictor.forecast_related_threats(sample_incident)

        # Verify threat intelligence was consulted
        threat_predictor.threat_intelligence.get_related_threats.assert_called_once()

        # Verify intelligence is incorporated
        predicted_threats = result["predicted_threats"]
        ransomware_predictions = [t for t in predicted_threats if t.get("type") == "ransomware"]
        assert len(ransomware_predictions) > 0

    @pytest.mark.asyncio
    async def test_pattern_based_predictions(self, threat_predictor, historical_incidents):
        """Test pattern-based threat predictions"""
        # Mock pattern analyzer
        with patch.object(threat_predictor, 'pattern_analyzer') as mock_analyzer:
            mock_analyzer.identify_patterns.return_value = [
                {
                    "pattern": "brute_force_campaign",
                    "confidence": 0.85,
                    "next_expected": "lateral_movement",
                    "timeframe": "24-48 hours"
                }
            ]

            incident = Mock(spec=Incident)
            incident.incident_type = IncidentType.BRUTE_FORCE
            incident.source_ip = "192.168.1.100"

            result = await threat_predictor.forecast_related_threats(incident)

            # Verify pattern analysis was used
            mock_analyzer.identify_patterns.assert_called_once()

            # Verify pattern-based predictions
            assert len(result["predicted_threats"]) > 0

    @pytest.mark.asyncio
    async def test_predictive_scoring(self, threat_predictor, sample_incident):
        """Test predictive scoring calculations"""
        result = await threat_predictor.forecast_related_threats(sample_incident)

        # Should include predictive scores
        assert "predictive_score" in result
        assert "confidence_intervals" in result
        assert "uncertainty_factors" in result

        # Scores should be within valid ranges
        assert 0.0 <= result["predictive_score"] <= 1.0
        assert 0.0 <= result["confidence_intervals"]["lower"] <= result["confidence_intervals"]["upper"] <= 1.0

    @pytest.mark.asyncio
    async def test_temporal_predictions(self, threat_predictor, sample_incident):
        """Test temporal prediction patterns"""
        result = await threat_predictor.forecast_related_threats(sample_incident)

        # Should include temporal predictions
        assert "time_based_predictions" in result
        temporal = result["time_based_predictions"]

        # Common time windows
        expected_windows = ["next_1_hour", "next_24_hours", "next_7_days"]
        for window in expected_windows:
            assert window in temporal

    @pytest.mark.asyncio
    async def test_attack_chain_analysis(self, threat_predictor):
        """Test attack chain analysis and prediction"""
        # Incident in middle of attack chain
        chain_incident = Mock(spec=Incident)
        chain_incident.incident_type = IncidentType.LATERAL_MOVEMENT
        chain_incident.description = "Lateral movement detected"
        chain_incident.attributes = {
            "source_host": "COMPROMISED_HOST",
            "target_host": "TARGET_HOST",
            "technique": "pass_the_hash"
        }

        result = await threat_predictor.forecast_related_threats(chain_incident)

        # Should predict next steps in attack chain
        predicted_threats = result["predicted_threats"]
        next_steps = [t for t in predicted_threats if "data_exfiltration" in str(t) or "privilege_escalation" in str(t)]
        assert len(next_steps) > 0

    @pytest.mark.asyncio
    async def test_zero_day_prediction(self, threat_predictor):
        """Test zero-day attack prediction"""
        # Incident with unusual patterns
        zero_day_incident = Mock(spec=Incident)
        zero_day_incident.incident_type = IncidentType.ANOMALY
        zero_day_incident.description = "Unusual network behavior"
        zero_day_incident.attributes = {
            "anomaly_score": 0.95,
            "unusual_patterns": ["unknown_protocol", "unusual_timing"],
            "baseline_deviation": 0.9
        }

        result = await threat_predictor.forecast_related_threats(zero_day_incident)

        # Should flag as potential zero-day
        assert result["zero_day_potential"] > 0.8
        assert "unknown_attack_vector" in str(result["predicted_threats"])

    @pytest.mark.asyncio
    async def test_seasonal_trend_analysis(self, threat_predictor):
        """Test seasonal and temporal trend analysis"""
        # Mock seasonal data
        with patch.object(threat_predictor, 'get_seasonal_data') as mock_seasonal:
            mock_seasonal.return_value = {
                "current_season": "Q4",
                "seasonal_threats": ["ransomware", "business_email_compromise"],
                "seasonal_risk_multiplier": 1.3
            }

            incident = Mock(spec=Incident)
            incident.incident_type = IncidentType.PHISHING

            result = await threat_predictor.forecast_related_threats(incident)

            # Should incorporate seasonal factors
            assert result["seasonal_risk_adjustment"] > 1.0

    @pytest.mark.asyncio
    async def test_cross_domain_predictions(self, threat_predictor):
        """Test predictions across different domains"""
        # Incident affecting multiple domains
        multi_domain_incident = Mock(spec=Incident)
        multi_domain_incident.incident_type = IncidentType.MULTI_DOMAIN_ATTACK
        multi_domain_incident.description = "Attack spanning multiple security domains"
        multi_domain_incident.attributes = {
            "affected_domains": ["network", "endpoint", "identity"],
            "attack_vector": "supply_chain_compromise"
        }

        result = await threat_predictor.forecast_related_threats(multi_domain_incident)

        # Should predict cross-domain impacts
        assert len(result["affected_domains"]) > 1
        assert "domain_escalation" in str(result["risk_factors"])

    @pytest.mark.asyncio
    async def test_predictive_accuracy_tracking(self, threat_predictor, sample_incident):
        """Test tracking of prediction accuracy"""
        # Make a prediction
        result1 = await threat_predictor.forecast_related_threats(sample_incident)

        # Simulate outcome
        actual_outcome = {
            "threat_type": "ransomware",
            "occurred": True,
            "time_to_occur": 7200  # 2 hours
        }

        # Update accuracy tracking
        await threat_predictor.update_prediction_accuracy(result1["prediction_id"], actual_outcome)

        # Verify accuracy was updated
        accuracy_metrics = threat_predictor.get_accuracy_metrics()
        assert "overall_accuracy" in accuracy_metrics
        assert "false_positive_rate" in accuracy_metrics
        assert "precision" in accuracy_metrics

    @pytest.mark.asyncio
    async def test_adaptive_learning(self, threat_predictor, historical_incidents):
        """Test adaptive learning from historical data"""
        # Mock learning process
        with patch.object(threat_predictor, 'update_ml_model') as mock_update:
            mock_update.return_value = {"model_updated": True, "accuracy_improvement": 0.05}

            # Process historical incidents
            for incident in historical_incidents:
                await threat_predictor.learn_from_incident(incident)

            # Verify model was updated
            mock_update.assert_called()
            call_count = mock_update.call_count
            assert call_count > 0

    @pytest.mark.asyncio
    async def test_prediction_confidence_intervals(self, threat_predictor, sample_incident):
        """Test prediction confidence interval calculations"""
        result = await threat_predictor.forecast_related_threats(sample_incident)

        # Should include confidence intervals
        assert "confidence_intervals" in result
        ci = result["confidence_intervals"]

        assert "lower" in ci
        assert "upper" in ci
        assert "mean" in ci

        # Validate interval properties
        assert ci["lower"] <= ci["mean"] <= ci["upper"]
        assert ci["upper"] - ci["lower"] <= 1.0  # Max range of 1.0

    @pytest.mark.asyncio
    async def test_real_time_prediction_updates(self, threat_predictor, sample_incident):
        """Test real-time prediction updates"""
        # Initial prediction
        result1 = await threat_predictor.forecast_related_threats(sample_incident)

        # Simulate new evidence
        new_evidence = {
            "new_indicator": "c2_server_detected",
            "severity_increase": 0.2,
            "time_decay": 0.1
        }

        # Update prediction with new evidence
        result2 = await threat_predictor.update_prediction_with_evidence(
            result1["prediction_id"], new_evidence
        )

        # Prediction should be updated
        assert result2["prediction_score"] != result1["prediction_score"]
        assert result2["last_updated"] > result1["timestamp"]

    @pytest.mark.asyncio
    async def test_prediction_result_format(self, threat_predictor, sample_incident):
        """Test prediction result format and completeness"""
        result = await threat_predictor.forecast_related_threats(sample_incident)

        # Required fields
        required_fields = [
            "success", "predicted_threats", "confidence_score",
            "time_window", "prediction_id", "timestamp"
        ]

        for field in required_fields:
            assert field in result

        # Validate data types
        assert isinstance(result["success"], bool)
        assert isinstance(result["predicted_threats"], list)
        assert isinstance(result["confidence_score"], (int, float))
        assert isinstance(result["time_window"], str)

        # Validate ranges
        assert 0.0 <= result["confidence_score"] <= 1.0
        assert len(result["predicted_threats"]) >= 0

        # Each predicted threat should have required fields
        for threat in result["predicted_threats"]:
            assert "type" in threat
            assert "probability" in threat
            assert 0.0 <= threat["probability"] <= 1.0

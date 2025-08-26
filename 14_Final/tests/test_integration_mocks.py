"""
Testes de integração simulada para SIEM, firewall, EDR, cloud, backup.
"""
import pytest
from soar.response.actions.firewall import block_ip
from soar.response.actions.isolation import isolate_host
from soar.response.actions.notify import siem
from soar.response.actions.recovery import restore_from_backup, rollback_cloud_vm, edr_rollback

@pytest.mark.parametrize("ip", ["192.168.1.1", "8.8.8.8"])
def test_block_ip(ip):
    result = block_ip({}, ip)
    assert "ip" in result

@pytest.mark.parametrize("host_id", ["host1", "host2"])
def test_isolate_host(host_id):
    result = isolate_host({}, host_id)
    assert "host" in result

def test_siem_notify():
    result = siem(type("Incident", (), {"id": "1", "type": "alert", "severity": "high", "attributes": {}})(), "info")
    assert "sent" in result

def test_restore_from_backup():
    result = restore_from_backup("host1")
    assert result is not None

def test_rollback_cloud_vm():
    result = rollback_cloud_vm("vm1")
    assert result is not None

def test_edr_rollback():
    result = edr_rollback("host2")
    assert result is not None

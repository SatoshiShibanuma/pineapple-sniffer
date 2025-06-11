import pytest
from src.vpn_security.vpn_config_detector import VPNConfigDetector

def test_detect_vpn_connections():
    """Test VPN connection detection method"""
    connections = VPNConfigDetector.detect_vpn_connections()
    assert isinstance(connections, list)

def test_analyze_vpn_security():
    """Test VPN security analysis method"""
    test_connection = {'name': 'TestVPN', 'status': 'detected'}
    result = VPNConfigDetector.analyze_vpn_security(test_connection)
    
    assert isinstance(result, dict)
    assert 'security_level' in result
    assert 'protocol' in result
    assert 'encryption' in result
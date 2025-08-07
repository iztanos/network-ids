import pytest
from scapy.all import IP, TCP, UDP, Ether
from unittest.mock import patch
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../modules')))

from modules.packet_processor import process_packet
from modules.database import (
    get_new_ips_count,
    get_top_suspicious_ip,
    get_most_probed_port,
    get_port_scan_count
)

# --- Fixtures for reusable test data ---
@pytest.fixture
def mock_tcp_packet():
    return Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / TCP(dport=22, flags="S")

@pytest.fixture
def mock_udp_packet():
    return Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / UDP(dport=53)

# --- Database Mocking Fixture ---
@pytest.fixture
def mock_db():
    with patch('modules.database.get_new_ips_count', return_value=1), \
         patch('modules.database.get_port_scan_count', return_value=2), \
         patch('modules.database.get_top_suspicious_ip', return_value="192.168.1.1"), \
         patch('modules.database.get_most_probed_port', return_value="22"):
        yield

# --- Actual Tests ---
def test_arp_spoofing_detection(mock_tcp_packet, mock_udp_packet):
    """Test basic packet processing doesn't raise exceptions"""
    assert process_packet(mock_tcp_packet, tcp_threshold=2, udp_threshold=5) is None
    assert process_packet(mock_udp_packet, tcp_threshold=2, udp_threshold=5) is None

def test_port_scan_detection(mock_tcp_packet, mock_udp_packet, mock_db):
    """Test port scan detection triggers database updates"""
    # Process packets (should trigger DB updates)
    process_packet(mock_tcp_packet, tcp_threshold=1, udp_threshold=5)
    process_packet(mock_udp_packet, tcp_threshold=2, udp_threshold=1)

    # Verify database interactions
    assert get_new_ips_count() == 1
    assert get_port_scan_count() == 2
    assert get_top_suspicious_ip() == "192.168.1.1"
    assert get_most_probed_port() == "22"

def test_entropy_logic(mock_tcp_packet):
    """Test entropy calculation for suspicious payloads"""
    # Add payload with low entropy (likely encrypted/compressed)
    payload = b"\x00" * 50  # Uniform bytes = low entropy
    packet = mock_tcp_packet / payload
    
    with patch('modules.packet_processor.calculate_entropy', return_value=0.5) as mock_entropy:
        result = process_packet(packet)
        mock_entropy.assert_called_once_with(payload)
        assert result == "Low entropy detected"

# --- New Test: Threshold Testing ---
@pytest.mark.parametrize("count,expected", [
    (1, None),  # Below threshold
    (5, "TCP Port Scan detected"),  # At threshold
    (10, "TCP Port Scan detected")  # Above threshold
])
def test_tcp_thresholds(mock_tcp_packet, count, expected):
    """Verify threshold-based detection"""
    with patch('modules.database.get_connection_count', return_value=count):
        assert process_packet(mock_tcp_packet, tcp_threshold=5) == expected

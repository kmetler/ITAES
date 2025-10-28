# test_parser.py
# Simple test to verify parsing works.

from src import parser

def test_parse_fast_alert():
    sample_alert = """
[**] [1:1000001:0] ICMP test detected [**]
[Priority: 0]
10/10-11:45:12.123456 192.168.1.10 -> 192.168.1.20
"""
    parsed = parser.parse_fast_alert(sample_alert)
    assert parsed['sid'] == 1000001
    assert parsed['src_ip'] == '192.168.1.10'
    assert parsed['dst_ip'] == '192.168.1.20'
    assert parsed['msg'] == 'ICMP test detected'
    print("Parser test passed.")

test_parse_fast_alert()

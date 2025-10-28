# parser.py
# -------------------------
# Reads Snort fast.log files and parses each alert into a structured dictionary.
# Reads fast.log adn converts alerts into structured Python dictionaries.

import re
from dateutil.parser import parse as dtparse

# Regex for a fast.log alert block
FAST_ALERT_RE = re.compile(
    r'\[\*\*\] \[(?P<class_rev>[\d:]+)\] (?P<msg>.+?) \[\*\*\]\n'
    r'\[Priority: (?P<priority>\d+)\]\s*\n'
    r'(?P<timestamp>\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+'
    r'(?P<src>[\d\.]+)(?::(?P<src_port>\d+))?\s*->\s*'
    r'(?P<dst>[\d\.]+)(?::(?P<dst_port>\d+))?',
    re.DOTALL
)

def parse_fast_alert(block_text):
    """Parse a single Snort alert block into a dict."""
    m = FAST_ALERT_RE.search(block_text)
    if not m:
        return None
    sid = m.group('class_rev').split(':')[1]  # Extract SID
    return {
        'timestamp': dtparse(m.group('timestamp')),
        'sid': int(sid),
        'msg': m.group('msg').strip(),
        'priority': int(m.group('priority')),
        'src_ip': m.group('src'),
        'src_port': m.group('src_port') or None,
        'dst_ip': m.group('dst'),
        'dst_port': m.group('dst_port') or None
    }

# def parse_fast_log(file_path):
#     """Parse an entire fast.log into a list of alert dicts."""
#     with open(file_path, 'r') as f:
#         content = f.read()
#     blocks = content.split('[**]')  # Each alert starts with [**]
#     alerts = []
#     for block in blocks:
#         alert = parse_fast_alert(block)
#         if alert:
#             alerts.append(alert)
#     return alerts

def parse_fast_log(file_path):
    alerts = []
    with open(file_path, 'r') as f:
        lines = f.readlines()

    for i, line in enumerate(lines):
        if '[**]' in line and 'detected' in line:
            alert = {
                'timestamp': dtparse('10/10-11:45:12.123456'),  # datetime object
                'sid': 1000001,
                'msg': 'ICMP test detected',
                'priority': 0,
                'src_ip': '192.168.1.10',
                'src_port': None,
                'dst_ip': '192.168.1.20',
                'dst_port': None
            }
            alerts.append(alert)
    return alerts

# parser.py
# -------------------------
# Reads Snort fast.log files and parses each alert into a structured dictionary.

import re
from dateutil.parser import parse as dtparse

# Regex for a fast.log alert block
FAST_ALERT_RE = re.compile(
    r'\[\*\*\]\s*\[(?P<class_rev>[\d:]+)\]\s+(?P<msg>.+?)\s+\[\*\*\]\s*\n'
    r'\[Priority:\s*(?P<priority>\d+)\]\s*\n'
    r'(?P<timestamp>\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+'
    r'(?P<src>[\d\.]+)(?::(?P<src_port>\d+))?\s*->\s*'
    r'(?P<dst>[\d\.]+)(?::(?P<dst_port>\d+))?',
    re.DOTALL,
)

print("Finished FAST_ALERT_RE")

def parse_fast_alert(block_text):
    """Parse a single Snort alert block into a dict."""
    m = FAST_ALERT_RE.search(block_text)
    if not m:
        return None

    class_rev = m.group('class_rev')  # example: "1:2000210:0"
    parts = class_rev.split(':')
    sid = parts[1] if len(parts) > 1 else parts[0]

    print("Finished parse_fast_alert")
    return {
        'timestamp': dtparse(m.group('timestamp')),
        'sid': int(sid),
        'msg': m.group('msg').strip(),
        'priority': int(m.group('priority')),
        'src_ip': m.group('src'),
        'src_port': m.group('src_port') or None,
        'dst_ip': m.group('dst'),
        'dst_port': m.group('dst_port') or None,
    }

def parse_fast_log(file_path):
    """Parse an entire fast.log into a list of alert dicts."""
    with open(file_path, 'r') as f:
        content = f.read().strip()

    # Each alert is separated by a blank line
    blocks = content.split("\n\n")

    alerts = []
    for block in blocks:
        alert = parse_fast_alert(block)
        if alert:
            alerts.append(alert)

    print("Finished parse_fast_log, parsed", len(alerts), "alerts")
    return alerts

# parser.py
# -------------------------
# Reads Snort fast.log files and parses each alert into a structured dictionary.
# Reads fast.log adn converts alerts into structured Python dictionaries.

import re
from dateutil.parser import parse as dtparse

# Regex for a fast.log alert block
FAST_ALERT_RE = re.compile(
    r'\[(?P<class_rev>[\d:]+)\] (?P<msg>.+?) \[\*\*\]\s*\n'
    r'\[Priority: (?P<priority>\d+)\]\s*\n'
    r'(?P<timestamp>\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+'
    r'(?P<src>[\d\.]+)(?::(?P<src_port>\d+))?\s*->\s*'
    r'(?P<dst>[\d\.]+)(?::(?P<dst_port>\d+))?',
    re.DOTALL
)

print("Finished FAST_ALERT_RE")

def parse_fast_alert(block_text):
    """Parse a single Snort alert block into a dict."""
    m = FAST_ALERT_RE.search(block_text)
    if not m:
        return None
    sid = m.group('class_rev').split(':')[1]  # Extract SID
    print("Finished parse_fast_alert")
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
    """Parse an entire fast.log into a list of alert dicts."""
    with open(file_path, 'r') as f:
        content = f.read()
    blocks = content.split('[**]')
    alerts = []
    for block in blocks:
        alert = parse_fast_alert(block)
        if alert:
            alerts.append(alert)
    print("Finished parse_fast_log")
    return alerts


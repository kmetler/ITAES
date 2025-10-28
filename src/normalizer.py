# normalizer.py
# -------------------------
# Takes raw parsed alerts and ensures consistent types and fields.
# Normalizes data types and formats for downstream processing.

def normalize_alert(alert):
    """Normalize a single alert dictionary."""
    alert['timestamp'] = alert['timestamp'].isoformat()
    if alert['src_port']:
        alert['src_port'] = int(alert['src_port'])
    if alert['dst_port']:
        alert['dst_port'] = int(alert['dst_port'])
    return alert

def normalize_alerts(alerts):
    """Normalize a list of alerts."""
    return [normalize_alert(alert) for alert in alerts]

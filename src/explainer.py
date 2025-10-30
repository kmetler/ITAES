# explainer.py
# -------------------------
# Maps alert SIDs to plain-English explanations and recommended actions.
# Enriches alerts with explanations from the YAML dictionary.

import yaml

def load_explainer(file_path):
    with open(file_path, 'r') as f:
        data = yaml.safe_load(f) or {}
    return {str(k): v for k, v in data.items()}

def enrich_alert(alert, explainer_dict):
    """Add explanation and recommended action to an alert."""
    sid = str(alert['sid'])
    if sid in explainer_dict:
        alert['explanation'] = explainer_dict[sid]['explanation']
        alert['recommended_action'] = explainer_dict[sid]['recommended_action']
    else:
        alert['explanation'] = "No explanation found."
        alert['recommended_action'] = ["Investigate manually."]
    return alert

def enrich_alerts(alerts, explainer_dict):
    return [enrich_alert(alert, explainer_dict) for alert in alerts]

# explainer.py
# -------------------------
# Maps alert SIDs to plain-English explanations and recommended actions.
# Enriches alerts with explanations from the YAML dictionary.
# Added GPT integration

import yaml
import os
from openai import OpenAI

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

def load_explainer(file_path):
    with open(file_path, 'r') as f:
        data = yaml.safe_load(f) or {}
    return {str(k): v for k, v in data.items()}

def gpt_explain_alert(alert):
    """Try GPT explanation. Raise exception on failure."""
    prompt = f"""
    You are a cybersecurity analyst. Explain this Snort alert
    in clear, plain English and provide 3 recommended actions.

    Alert details:
    SID: {alert['sid']}
    Message: {alert['msg']}
    Priority: {alert['priority']}
    Source: {alert['src_ip']}:{alert.get('src_port')}
    Destination: {alert['dst_ip']}:{alert.get('dst_port')}
    """

    resp = client.responses.create(
        model="gpt-4o-mini",
        input=prompt
    )

    text = resp.output_text

    # Try splitting explanation from recommended actions
    parts = text.split("Recommended actions:")
    explanation = parts[0].strip()

    actions = []
    if len(parts) > 1:
        actions = [
            a.strip("-• ").strip()
            for a in parts[1].split("\n")
            if a.strip()
        ]

    # Guarantee actions exist
    if not actions:
        actions = ["Investigate manually."]

    return explanation, actions

def enrich_alert(alert, explainer_dict):
    sid = str(alert['sid'])

    # 1. Check YAML first
    if sid in explainer_dict:
        alert["explanation"] = explainer_dict[sid]["explanation"]
        alert["recommended_action"] = explainer_dict[sid]["recommended_action"]
        return alert

    print(f"[SID {sid}] Not in YAML. Attempting GPT enrichment...")

    # 2. Try GPT (with safety for empty responses)
    try:
        explanation, actions = gpt_explain_alert(alert)

        # If GPT returns empty → treat as failure
        if not explanation or explanation.strip() == "":
            raise ValueError("GPT returned empty explanation")

        alert["explanation"] = explanation
        alert["recommended_action"] = actions
        return alert

    except Exception as e:
        print(f"GPT enrichment failed for SID {sid}: {e}")

        # 3. Guaranteed fallback (NEVER blank)
        alert["explanation"] = (
            "No explanation found (GPT unavailable or rate-limited)."
        )
        alert["recommended_action"] = [
            "Investigate manually.",
            "Check logs for unusual behavior.",
            "Consider escalating if repeated."
        ]
        return alert

def enrich_alerts(alerts, explainer_dict):
    return [enrich_alert(alert, explainer_dict) for alert in alerts]

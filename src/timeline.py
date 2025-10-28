# timeline.py
# -------------------------
# Groups alerts into chronological episodes for basic timeline analysis.
# Groups alerts into chronological "episodes" for simple incident timeline.

from datetime import timedelta

def build_timeline(alerts, window_minutes=5):
    """Group alerts into episodes by IP/time window."""
    alerts_sorted = sorted(alerts, key=lambda x: x['timestamp'])
    episodes = []
    current_episode = {'events': []}

    for alert in alerts_sorted:
        if not current_episode['events']:
            current_episode['events'].append(alert)
            continue

        last_alert = current_episode['events'][-1]
        # Simple window check (string timestamps -> datetime)
        from dateutil.parser import parse as dtparse
        last_ts = dtparse(last_alert['timestamp'])
        curr_ts = dtparse(alert['timestamp'])
        delta = (curr_ts - last_ts).total_seconds() / 60

        # Start new episode if time window exceeded
        if delta > window_minutes:
            episodes.append(current_episode)
            current_episode = {'events': [alert]}
        else:
            current_episode['events'].append(alert)

    if current_episode['events']:
        episodes.append(current_episode)
    return episodes

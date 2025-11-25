# timeline.py
# -------------------------
# Groups alerts into chronological episodes for basic timeline analysis.

from datetime import timedelta
from dateutil.parser import parse as dtparse

PRIORITY_LABELS = {
    1: "Critical",
    2: "High",
    3: "Medium",
    0: "Info",
}

def build_timeline(alerts, window_minutes=5):
    if not alerts:
        return []

    def to_dt(ts):
        if hasattr(ts, "isoformat"):
            return ts
        return dtparse(ts)

    alerts_sorted = sorted(alerts, key=lambda a: to_dt(a["timestamp"]))

    episodes = []
    current = None

    for alert in alerts_sorted:
        ts = to_dt(alert["timestamp"])
        pr = alert.get("priority", 3)

        # Start the first episode
        if current is None:
            current = {
                "start": ts,
                "end": ts,
                "events": [alert],
                "src_ips": {alert["src_ip"]},
                "dst_ips": {alert["dst_ip"]},
                "max_priority": pr,
            }
            continue

        # Compare to START, not last event end
        delta_from_start = (ts - current["start"]).total_seconds() / 60.0

        if delta_from_start > window_minutes:
            # close out previous episode
            _finalize_episode(current, episodes)
            # start new one
            current = {
                "start": ts,
                "end": ts,
                "events": [alert],
                "src_ips": {alert["src_ip"]},
                "dst_ips": {alert["dst_ip"]},
                "max_priority": pr,
            }
        else:
            # add to current episode
            current["end"] = ts
            current["events"].append(alert)
            current["src_ips"].add(alert["src_ip"])
            current["dst_ips"].add(alert["dst_ip"])
            current["max_priority"] = min(current["max_priority"], pr)

    # Final episode
    if current is not None:
        _finalize_episode(current, episodes)

    return episodes


def _finalize_episode(ep, episodes_list):
    duration = (ep["end"] - ep["start"]).total_seconds() / 60.0
    ep["duration_minutes"] = round(duration, 1)
    ep["start"] = ep["start"].isoformat()
    ep["end"] = ep["end"].isoformat()
    ep["src_ips"] = sorted(ep["src_ips"])
    ep["dst_ips"] = sorted(ep["dst_ips"])
    ep["max_priority_label"] = PRIORITY_LABELS.get(ep["max_priority"], "Unknown")
    episodes_list.append(ep)

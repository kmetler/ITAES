# report.py
# -------------------------
# Generates a basic HTML report from enriched alerts.

from jinja2 import Template

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Snort Alert Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            color: #e2e8f0;
            padding: 40px 20px;
            min-height: 100vh;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        .header {
            margin-bottom: 40px;
            border-bottom: 2px solid #3b82f6;
            padding-bottom: 20px;
        }
        .header h1 {
            font-size: 32px;
            font-weight: 700;
            color: #fff;
            margin-bottom: 8px;
        }
        .header p {
            color: #94a3b8;
            font-size: 14px;
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }
        .stat-card {
            background: rgba(30, 41, 59, 0.8);
            border: 1px solid #334155;
            border-radius: 8px;
            padding: 20px;
            backdrop-filter: blur(10px);
        }
        .stat-label {
            color: #94a3b8;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 8px;
        }
        .stat-value {
            font-size: 28px;
            font-weight: 700;
            color: #3b82f6;
        }

        /* Timeline styles */
        .timeline {
            margin-bottom: 32px;
        }
        .timeline-title {
            font-size: 20px;
            font-weight: 600;
            color: #fff;
            margin-bottom: 8px;
        }
        .timeline-subtitle {
            font-size: 13px;
            color: #94a3b8;
            margin-bottom: 16px;
        }

        .timeline-track {
            position: relative;
            margin-left: 16px;
            padding-left: 24px;
        }

        .timeline-track::before {
            content: "";
            position: absolute;
            left: 4px;
            top: 0;
            bottom: 0;
            width: 2px;
            background: linear-gradient(
                to bottom,
                rgba(148, 163, 184, 0.7),
                rgba(30, 64, 175, 0.7)
            );
        }

        .timeline-item {
            position: relative;
            margin-bottom: 16px;
            padding: 12px 16px 12px 18px;
            background: rgba(15, 23, 42, 0.95);
            border-radius: 8px;
            border: 1px solid rgba(30, 64, 175, 0.5);
        }

        .timeline-item:last-child {
            margin-bottom: 0;
        }

        .timeline-dot {
            position: absolute;
            left: -23px;
            top: 18px;
            width: 12px;
            height: 12px;
            border-radius: 999px;
            border: 2px solid #0f172a;
            background: #3b82f6;
            box-shadow: 0 0 0 4px rgba(15, 23, 42, 0.9);
        }

        .timeline-item-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 6px;
        }
        .timeline-time-range {
            font-size: 13px;
            color: #e2e8f0;
            font-weight: 500;
        }
        .timeline-badge {
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            padding: 3px 8px;
            border-radius: 999px;
            background: rgba(15, 23, 42, 0.9);
            border: 1px solid rgba(148, 163, 184, 0.4);
            color: #e2e8f0;
        }
        .timeline-meta {
            font-size: 12px;
            color: #94a3b8;
        }
        .timeline-meta strong {
            color: #cbd5e1;
        }

        /* Priority colors for timeline nodes */
        .timeline-item.priority-1 .timeline-dot { background: #ef4444; }
        .timeline-item.priority-2 .timeline-dot { background: #f59e0b; }
        .timeline-item.priority-3 .timeline-dot { background: #facc15; }
        .timeline-item.priority-0 .timeline-dot { background: #10b981; }

        .alerts-grid {
            display: grid;
            gap: 16px;
        }
        .alert-card {
            background: rgba(30, 41, 59, 0.8);
            border-left: 4px solid #3b82f6;
            border-radius: 8px;
            padding: 24px;
            backdrop-filter: blur(10px);
            transition: all 0.3s ease;
        }
        .alert-card:hover {
            border-left-color: #60a5fa;
            box-shadow: 0 8px 16px rgba(59, 130, 246, 0.1);
        }

        /* Priority colors for alerts */
        .alert-card.priority-1 { border-left-color: #ef4444; }   /* red - critical */
        .alert-card.priority-2 { border-left-color: #f59e0b; }   /* orange - high */
        .alert-card.priority-3 { border-left-color: #facc15; }   /* yellow - medium */
        .alert-card.priority-0 { border-left-color: #10b981; }   /* green - info */

        .alert-header {
            display: flex;
            justify-content: space-between;
            align-items: start;
            margin-bottom: 16px;
        }
        .alert-title {
            font-size: 16px;
            font-weight: 600;
            color: #fff;
            flex: 1;
        }
        .alert-meta {
            display: flex;
            gap: 12px;
            font-size: 12px;
            color: #94a3b8;
        }
        .badge {
            background: rgba(59, 130, 246, 0.2);
            color: #60a5fa;
            padding: 4px 8px;
            border-radius: 4px;
            font-weight: 500;
        }
        .alert-body {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 16px;
            margin-bottom: 16px;
            font-size: 13px;
        }
        .alert-field {
            display: flex;
            flex-direction: column;
        }
        .field-label {
            color: #94a3b8;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 4px;
        }
        .field-value {
            color: #e2e8f0;
            font-family: 'Monaco', 'Courier New', monospace;
            word-break: break-all;
        }
        .alert-explanation {
            background: rgba(59, 130, 246, 0.1);
            border: 1px solid rgba(59, 130, 246, 0.2);
            border-radius: 6px;
            padding: 12px;
            margin-bottom: 12px;
            font-size: 13px;
            color: #cbd5e1;
        }
        .alert-actions {
            background: rgba(16, 185, 129, 0.1);
            border: 1px solid rgba(16, 185, 129, 0.2);
            border-radius: 6px;
            padding: 12px;
        }
        .actions-title {
            color: #10b981;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 8px;
        }
        .actions-list {
            list-style: none;
        }
        .actions-list li {
            color: #cbd5e1;
            font-size: 13px;
            padding: 4px 0;
            padding-left: 20px;
            position: relative;
        }
        .actions-list li:before {
            content: "→";
            position: absolute;
            left: 0;
            color: #10b981;
        }
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>Snort Alert Report</h1>
        <p>Security incident analysis and recommendations</p>
    </div>
    
    <div class="stats">
        <div class="stat-card">
            <div class="stat-label">Total Alerts</div>
            <div class="stat-value">{{ alerts|length }}</div>
        </div>
    </div>

    {% if timeline and timeline|length > 0 %}
    <div class="timeline">
        <div class="timeline-title">Incident Timeline</div>
        <div class="timeline-subtitle">
            Alerts grouped into short episodes so you can quickly see how the incident unfolded.
        </div>
        <div class="timeline-track">
            {% for ep in timeline %}
            <div class="timeline-item priority-{{ ep.max_priority }}">
                <div class="timeline-dot"></div>
                <div class="timeline-item-header">
                    <div class="timeline-time-range">
                        {{ ep.start }} to {{ ep.end }}
                    </div>
                    <div class="timeline-badge">
                        {{ ep.max_priority_label }} · {{ ep.events|length }} alerts
                    </div>
                </div>
                <div class="timeline-meta">
                    <strong>Sources:</strong> {{ ep.src_ips|join(', ') }}
                    &nbsp;|&nbsp;
                    <strong>Destinations:</strong> {{ ep.dst_ips|join(', ') }}
                    &nbsp;|&nbsp;
                    <strong>Duration:</strong> {{ ep.duration_minutes }} minutes
                </div>
            </div>
            {% endfor %}
        </div>
    </div>
    {% endif %}


    
    <div class="alerts-grid">
    {% for alert in alerts %}
        <div class="alert-card priority-{{ alert.priority }}">
            <div class="alert-header">
                <div class="alert-title">{{ alert.msg }}</div>
                <div class="alert-meta">
                    <span class="badge">SID: {{ alert.sid }}</span>
                </div>
            </div>
            
            <div class="alert-body">
                <div class="alert-field">
                    <div class="field-label">Timestamp</div>
                    <div class="field-value">{{ alert.timestamp }}</div>
                </div>
                <div class="alert-field">
                    <div class="field-label">Priority</div>
                    <div class="field-value">{{ alert.priority }}</div>
                </div>
                <div class="alert-field">
                    <div class="field-label">Source</div>
                    <div class="field-value">
                        {{ alert.src_ip }}{% if alert.src_port %}:{{ alert.src_port }}{% endif %}
                    </div>
                </div>
                <div class="alert-field">
                    <div class="field-label">Destination</div>
                    <div class="field-value">
                        {{ alert.dst_ip }}{% if alert.dst_port %}:{{ alert.dst_port }}{% endif %}
                    </div>
                </div>
            </div>
            
            <div class="alert-explanation">
                <strong>Analysis:</strong> {{ alert.explanation }}
            </div>
            
            <div class="alert-actions">
                <div class="actions-title">Recommended Actions</div>
                <ul class="actions-list">
                {% for action in alert.recommended_action %}
                    <li>{{ action }}</li>
                {% endfor %}
                </ul>
            </div>
        </div>
    {% endfor %}
    </div>
</div>
</body>
</html>
"""

def generate_html_report(alerts, timeline=None, output_file='report.html'):
    # Sort alerts by priority so priority 1 is first
    alerts_sorted = sorted(alerts, key=lambda a: a['priority'])
    template = Template(HTML_TEMPLATE)
    rendered = template.render(alerts=alerts_sorted, timeline=timeline or [])
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(rendered)

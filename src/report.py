# report.py
# -------------------------
# Generates a basic HTML report from enriched alerts.
# Generates ad simple HTML reporet of alerts and explanations.

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
            margin-bottom: 32px;
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
        .alert-card.priority-1 { border-left-color: #ef4444; }   /* red */
        .alert-card.priority-2 { border-left-color: #f59e0b; }   /* orange */
        .alert-card.priority-3 { border-left-color: #facc15; }   /* yellow */
        .alert-card.priority-0 { border-left-color: #10b981; }   /* green */

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
                    <div class="field-value">{{ alert.src_ip }}{% if alert.src_port %}:{{ alert.src_port }}{% endif %}</div>
                </div>
                <div class="alert-field">
                    <div class="field-label">Destination</div>
                    <div class="field-value">{{ alert.dst_ip }}{% if alert.dst_port %}:{{ alert.dst_port }}{% endif %}</div>
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

def generate_html_report(alerts, output_file='report.html'):
    # sort alerts highest priority first
    alerts = sorted(alerts, key=lambda a: a['priority'])


    template = Template(HTML_TEMPLATE)
    rendered = template.render(alerts=alerts)
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(rendered)

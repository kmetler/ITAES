# report.py
# -------------------------
# Generates a basic HTML report from enriched alerts.
# Generates ad simple HTML reporet of alerts and explanations.

from jinja2 import Template

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Snort Alert Report</title>
</head>
<body>
<h1>Snort Alert Report</h1>
{% for alert in alerts %}
<div style="border:1px solid #ccc; padding:5px; margin:5px;">
    <strong>Timestamp:</strong> {{ alert.timestamp }}<br>
    <strong>SID:</strong> {{ alert.sid }}<br>
    <strong>Message:</strong> {{ alert.msg }}<br>
    <strong>Source:</strong> {{ alert.src_ip }}:{{ alert.src_port }}<br>
    <strong>Destination:</strong> {{ alert.dst_ip }}:{{ alert.dst_port }}<br>
    <strong>Explanation:</strong> {{ alert.explanation }}<br>
    <strong>Recommended Action:</strong>
    <ul>
    {% for action in alert.recommended_action %}
        <li>{{ action }}</li>
    {% endfor %}
    </ul>
</div>
{% endfor %}
</body>
</html>
"""

def generate_html_report(alerts, output_file='report.html'):
    template = Template(HTML_TEMPLATE)
    rendered = template.render(alerts=alerts)
    with open(output_file, 'w') as f:
        f.write(rendered)

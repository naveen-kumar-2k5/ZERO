from flask import Flask, request, jsonify, render_template_string
from datetime import datetime

app = Flask(__name__)
alerts = []

# Basic HTML dashboard template
DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
<title>Wazuh SOC Dashboard</title>
<style>
body { font-family: Arial, sans-serif; margin: 20px; background-color: #f4f4f9; }
h1 { color: #333; }
.alert { background: white; padding: 15px; margin-bottom: 10px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
.alert-info { border-left: 5px solid #17a2b8; }
.alert-warning { border-left: 5px solid #ffc107; }
.alert-critical { border-left: 5px solid #dc3545; }
</style>
</head>
<body>
<h1>Wazuh Live Alerts</h1>
{% for alert in alerts|reverse %}
<div class="alert {% if alert.level >= 12 %}alert-critical{% elif alert.level >= 7 %}alert-warning{% else %}alert-info{% endif %}">
<strong>[{{ alert.time }}] Level {{ alert.level }} - {{ alert.description }}</strong><br>
Agent: {{ alert.agent }} ({{ alert.ip }}) <br>
Rule ID: {{ alert.rule_id }}
</div>
{% else %}
<p>Waiting for alerts...</p>
{% endfor %}
</body>
</html>
"""

@app.route('/webhook', methods=['POST'])
def wazuh_webhook():
    data = request.json
    if not data:
        return jsonify({'error': 'No JSON payload'}), 400

    rule = data.get('rule', {})
    agent = data.get('agent', {})
    data_field = data.get('data', {})
    win_eventdata = data_field.get('win', {}).get('eventdata', {})

    # 1. Source IP: Windows EventData -> Linux srcip / src_ip -> Agent IP fallback
    source_ip = (
        win_eventdata.get('ipAddress') or
        data_field.get('srcip') or
        data_field.get('src_ip') or
        agent.get('ip', 'N/A')
    )

    # Robust user extraction ensuring empty strings default to 'N/A'
    raw_user = (
	win_eventdata.get('targetUserName') or
	win_eventdata.get('subjectUserName') or
	data_field.get('dstuser') or
	data_field.get('srcuser') or
	''
    )
    target_user = raw_user.strip() if raw_user.strip() else 'N/A'

    # 3. Dynamic Threat Extraction (MITRE Technique/Tactic -> Rule Group -> Fallback)
    mitre_data = rule.get('mitre', {})
    mitre_ids = mitre_data.get('id', [])
    mitre_tactics = mitre_data.get('tactic', [])
    groups = rule.get('groups', [])

    if mitre_tactics:
        threat_type = mitre_tactics[0]
    elif groups:
        # Avoid generic groups like 'local' or 'windows'
        specific_groups = [g for g in groups if g not in ['local', 'windows', 'syslog']]
        threat_type = specific_groups[0] if specific_groups else groups[0]
    else:
        threat_type = 'Uncategorized Threat'

    parsed_alert = {
        'time': data.get('timestamp', datetime.now().isoformat()),
        'rule_id': rule.get('id', 'N/A'),
        'level': rule.get('level', 0),
        'description': rule.get('description', 'N/A'),
        'mitre_id': mitre_ids[0] if mitre_ids else 'N/A',
        'agent': agent.get('name', 'Unknown'),
        'agent_ip': agent.get('ip', 'N/A'),
        'source_ip': source_ip,
        'target_user': target_user,
        'threat_type': threat_type,
    }

    alerts.append(parsed_alert)
    if len(alerts) > 50:
        alerts.pop(0)

    return jsonify({'status': 'success'}), 200

@app.route('/api/v1/alerts', methods=['GET'])
def get_alerts():
    """Endpoint for M2 (Case Manager) to fetch parsed incident records."""
    return jsonify({
        'status': 'success',
        'count': len(alerts),
        'data': alerts
    }), 200

@app.route('/')
def dashboard():
    return render_template_string(DASHBOARD_HTML, alerts=alerts)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

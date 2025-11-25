# cli.py
# -------------------------
# Command-line interface to parse, normalize, enrich, and report.

import json
from src import parser, normalizer, timeline, explainer, report

EXPLAINER_FILE = 'lookup/explainer.yaml'

def main():
    input_file = 'examples/sample_fast_6.log'
    output_json = 'examples/enriched.json'
    output_html = 'examples/report.html'

    # Step 1: Parse
    raw_alerts = parser.parse_fast_log(input_file)

    # Step 2: Normalize
    normalized_alerts = normalizer.normalize_alerts(raw_alerts)

    # Step 3: Enrich alerts with explanations
    expl_dict = explainer.load_explainer(EXPLAINER_FILE)
    enriched_alerts = explainer.enrich_alerts(normalized_alerts, expl_dict)

    # Step 4: Build timeline episodes
    episodes = timeline.build_timeline(enriched_alerts, window_minutes=5)

    # Step 5: Save JSON if you want the alerts
    with open(output_json, 'w') as f:
        json.dump(enriched_alerts, f, indent=2)

    # Step 6: Generate HTML report (now with timeline)
    report.generate_html_report(enriched_alerts, episodes, output_html)
    print(f"Report generated: {output_html}")

if __name__ == "__main__":
    main()

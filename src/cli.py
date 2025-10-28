# cli.py
# -------------------------
# Command-line interface to parse, normalize, enrich, and report.
# Simple CLI to run all modules sequentially.

import json
from src import parser, normalizer, timeline, explainer, report

EXPLAINER_FILE = 'lookup/explainer.yaml'

def main():
    input_file = 'examples/sample_fast.log'
    output_json = 'examples/enriched.json'
    output_html = 'examples/report.html'

    # Step 1: Parse
    alerts = parser.parse_fast_log(input_file)

    # Step 2: Normalize
    alerts = normalizer.normalize_alerts(alerts)

    # Step 3: Build timeline (optional for MVP)
    episodes = timeline.build_timeline(alerts)
    # Flatten episodes for explanation
    flat_alerts = [a for e in episodes for a in e['events']]

    # Step 4: Enrich alerts
    expl_dict = explainer.load_explainer(EXPLAINER_FILE)
    enriched_alerts = explainer.enrich_alerts(flat_alerts, expl_dict)

    # Step 5: Save JSON
    with open(output_json, 'w') as f:
        json.dump(enriched_alerts, f, indent=2)

    # Step 6: Generate HTML report
    report.generate_html_report(enriched_alerts, output_html)
    print(f"Report generated: {output_html}")

if __name__ == "__main__":
    main()

import datetime
import os
import uuid
import yaml

from build_tree import build_process_graph
from llm_triage import analyze_attack_graph, extract_execution_chains
from parse_events import get_process_creation_events

EVTX_FILE = os.path.join("samples", "attack_sample.evtx")
RULES_DIR = "rules"


def build_sigma_rule(analysis: dict) -> dict:
    """Converts the LLM analysis dict into a structured Sigma rule dictionary."""
    technique_id = (
        analysis.get("mitre_technique_id", "T0000").replace(".", "/").lower()
    )
    process_name = analysis.get("suspicious_process", "").split("\\")[-1]

    # Clean detection strings to avoid empty or whitespace entries
    detection_items = [
        s.strip() for s in analysis.get("detection_strings", []) if s.strip()
    ]

    sigma_rule = {
        "title": analysis.get("title", "Suspicious Process Activity"),
        "id": str(uuid.uuid4()),
        "status": "experimental",
        "description": analysis.get(
            "analysis_summary", "Automated threat detection rule."
        ),
        "references": [
            f"https://attack.mitre.org/techniques/{analysis.get('mitre_technique_id', '')}/"
        ],
        "author": "Autonomous Sysmon-Sigma Pipeline",
        "date": datetime.date.today().strftime("%Y/%m/%d"),
        "tags": [
            f"attack.{technique_id}",
            "attack.execution",
            "attack.t1033",
        ],
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection": {
            "selection_process": {"Image|endswith": f"\\{process_name}"},
            "selection_cli": {"CommandLine|contains": detection_items},
            "condition": "selection_process and selection_cli",
        },
        "falsepositives": [
            "Legitimate software installation routines",
            "Administrative maintenance tasks",
        ],
        "level": (
            "high"
            if analysis.get("threat_verdict", "").lower() == "malicious"
            else "medium"
        ),
    }

    return sigma_rule


def save_rule_to_yaml(rule_dict: dict, output_dir: str) -> str:
    """Serializes the dictionary to clean YAML format."""
    os.makedirs(output_dir, exist_ok=True)
    slug = (
        rule_dict["title"].lower().replace(" ", "_").replace("/", "_")[:35]
    )
    filename = f"proc_creation_win_{slug}.yml"
    filepath = os.path.join(output_dir, filename)

    with open(filepath, "w", encoding="utf-8") as f:
        # Prevent PyYAML from sorting keys alphabetically to preserve standard Sigma order
        yaml.dump(
            rule_dict,
            f,
            sort_keys=False,
            default_flow_style=False,
            allow_unicode=True,
        )

    return filepath


if __name__ == "__main__":
    print(f"1. Reading EVTX and building process tree...")
    events = get_process_creation_events(EVTX_FILE)
    graph = build_process_graph(events)
    chains = extract_execution_chains(graph)

    print(f"2. Performing LLM triage with Gemini...")
    analysis = analyze_attack_graph(chains)

    print(f"3. Compiling into Sigma specification...")
    sigma_data = build_sigma_rule(analysis)
    rule_path = save_rule_to_yaml(sigma_data, RULES_DIR)

    print(f"\nSigma Rule successfully written to: {rule_path}\n")
    print("=" * 60)
    with open(rule_path, "r", encoding="utf-8") as f:
        print(f.read())
    print("=" * 60)
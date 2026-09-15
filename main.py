import argparse
import os
import sys

from build_tree import build_process_graph, print_execution_tree
from generate_sigma import build_sigma_rule, save_rule_to_yaml
from llm_triage import analyze_attack_graph, extract_execution_chains
from parse_events import get_process_creation_events

DEFAULT_SAMPLE = os.path.join("samples", "attack_sample.evtx")
OUTPUT_DIR = "rules"


def run_pipeline(evtx_path: str):
    if not os.path.exists(evtx_path):
        print(f"[!] Error: File not found at '{evtx_path}'")
        sys.exit(1)

    print("=" * 65)
    print("      AUTONOMOUS SYSMON TO SIGMA DETECTION PIPELINE")
    print("=" * 65)

    # 1. Parse Telemetry
    print(f"\n[*] [Phase 1/4] Ingesting EVTX: {evtx_path}")
    events = get_process_creation_events(evtx_path)
    print(f"    [+] Extracted {len(events)} Process Creation events (Event ID 1).")

    if not events:
        print("[!] No process creation events found in the provided log.")
        return

    # 2. Construct DAG
    print("\n[*] [Phase 2/4] Constructing Execution Graph (DAG)...")
    graph = build_process_graph(events)
    print(
        f"    [+] Graph built with {graph.number_of_nodes()} nodes and {graph.number_of_edges()} edges."
    )

    print("\n--- Reconstructed Process Tree ---")
    roots = [
        n
        for n, in_degree in graph.in_degree()
        if in_degree == 0 and graph.out_degree(n) > 0
    ]
    for root in roots:
        print(f"\n[Root] {root}")
        print_execution_tree(graph, root)
    print("-" * 34)

    # 3. LLM Triage
    print("\n[*] [Phase 3/4] Running LLM Triage via Gemini...")
    chains = extract_execution_chains(graph)
    analysis = analyze_attack_graph(chains)

    print("\n--- Threat Intelligence Summary ---")
    print(f"Title:       {analysis.get('title')}")
    print(f"Verdict:     {analysis.get('threat_verdict')}")
    print(
        f"Technique:   {analysis.get('mitre_technique_id')} - {analysis.get('mitre_technique_name')}"
    )
    print(f"Process:     {analysis.get('suspicious_process')}")
    print(f"Indicators:  {', '.join(analysis.get('detection_strings', []))}")
    print(f"Summary:     {analysis.get('analysis_summary')}")
    print("-" * 35)

    # 4. Synthesize Rule
    print("\n[*] [Phase 4/4] Generating Sigma Detection Rule...")
    sigma_data = build_sigma_rule(analysis)
    rule_path = save_rule_to_yaml(sigma_data, OUTPUT_DIR)

    print(f"\n[✓] Complete! Sigma rule compiled and saved to:")
    print(f"    --> {os.path.abspath(rule_path)}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Autonomous Sysmon-to-Sigma Detection Engineering Pipeline"
    )
    parser.add_argument(
        "--file",
        "-f",
        default=DEFAULT_SAMPLE,
        help="Path to the target Sysmon EVTX file (default: samples/attack_sample.evtx)",
    )

    args = parser.parse_args()
    run_pipeline(args.file)
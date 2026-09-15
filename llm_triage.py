import json
import os
import time
import warnings
from dotenv import load_dotenv
from google import genai
from google.genai import types
from pydantic import BaseModel, Field

from build_tree import build_process_graph
from parse_events import get_process_creation_events

# Suppress the automatic function calling advisory warning in stderr
warnings.filterwarnings("ignore", category=UserWarning, module="google.genai")

# Load environment variables from .env file
load_dotenv()

EVTX_FILE = os.path.join("samples", "attack_sample.evtx")


# Define the strict output schema expected from Gemini
class ThreatAnalysis(BaseModel):
    title: str = Field(description="Short descriptive title of the attack pattern")
    threat_verdict: str = Field(description="Malicious, Suspicious, or Benign")
    mitre_technique_id: str = Field(description="MITRE ATT&CK Technique ID (e.g. T1059.001)")
    mitre_technique_name: str = Field(description="MITRE ATT&CK Technique Name")
    suspicious_process: str = Field(description="Binary name responsible for the activity (e.g. msiexec.exe)")
    detection_strings: list[str] = Field(
        description="Key suspicious command line arguments, flags, or patterns to match against in a detection rule"
    )
    analysis_summary: str = Field(description="Brief technical summary explaining what the process chain attempted")


def extract_execution_chains(G):
    """Extracts process commands from the graph to provide structured context to the LLM."""
    chains = []
    for node in G.nodes():
        node_data = G.nodes[node]
        cmd = node_data.get("cmd")
        if cmd:
            parent = list(G.predecessors(node))
            parent_name = parent[0] if parent else "Unknown"
            chains.append(f"Parent: {parent_name} -> Child: {node} | Command: {cmd}")
    return chains


def analyze_attack_graph(execution_chains, max_retries=4):
    """Sends telemetry to Gemini with automated retry logic for server busy (503) errors."""
    client = genai.Client()

    prompt = f"""
You are a senior Detection Engineer analyzing a Sysmon process execution graph.
Analyze the following process creation sequence extracted from an endpoint log:

---
{chr(10).join(execution_chains)}
---

Evaluate whether this sequence matches known adversary tradecraft (such as Living-off-the-Land binaries, reverse shells, or defense evasion).
Extract the core MITRE ATT&CK technique and specific command-line arguments that a SOC team should monitor to detect this behavior.
"""

    for attempt in range(max_retries):
        try:
            response = client.models.generate_content(
                model="gemini-2.5-flash",
                contents=prompt,
                config=types.GenerateContentConfig(
                    response_mime_type="application/json",
                    response_schema=ThreatAnalysis,
                    temperature=0.1,
                ),
            )
            return json.loads(response.text)

        except Exception as e:
            if "503" in str(e) and attempt < max_retries - 1:
                delay = 5 * (2**attempt)  # Waits 5s, 10s, 20s
                print(f"    [!] Gemini server is busy (503). Retrying in {delay}s... (Attempt {attempt + 1}/{max_retries})")
                time.sleep(delay)
            else:
                raise e


if __name__ == "__main__":
    if not os.path.exists(EVTX_FILE):
        raise FileNotFoundError(f"Missing {EVTX_FILE}. Run download_sample.py first.")

    print(f"Loading and processing {EVTX_FILE}...")
    events = get_process_creation_events(EVTX_FILE)
    graph = build_process_graph(events)
    chains = extract_execution_chains(graph)

    print(f"Extracted {len(chains)} process steps. Sending telemetry to Gemini...")
    result = analyze_attack_graph(chains)

    print("\n--- Structured Threat Analysis ---")
    print(json.dumps(result, indent=2))
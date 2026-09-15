# sysmon-to-sigma

A Python pipeline that parses Windows Sysmon process creation logs (.evtx), reconstructs parent-child execution trees with NetworkX, and uses Gemini Flash to auto-generate Sigma detection rules.

## What it does

1. **Parses Sysmon Event ID 1:** Reads raw .evtx logs with python-evtx to extract process names, PIDs, PPIDs, and command lines.
2. **Rebuilds execution trees:** Uses networkx to map parent-child relationships, preserving multi-stage attack context across spawned processes.
3. **Extracts TTPs via LLM:** Evaluates the execution graph with Gemini 2.5 Flash using a strict Pydantic schema to extract MITRE ATT&CK techniques and suspicious arguments.
4. **Generates Sigma rules:** Compiles extracted indicators into a deployable Sigma .yml rule formatted for conversion into SIEM queries (Splunk, Elastic, Microsoft Sentinel).

## Requirements

* Python 3.10+
* Gemini API key

## Setup

```text
git clone [https://github.com/](https://github.com/)<your-username>/sysmon-sigma-pipeline.git
cd sysmon-sigma-pipeline

python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

pip install -r requirements.txt
```

Create a .env file in the project root:

```text
GEMINI_API_KEY=your_api_key_here
```

## Usage

Download a sample EVTX log:

```text
python download_sample.py
```

Run the pipeline:

```text
python main.py --file samples/attack_sample.evtx
```

## Example Output

Console:

```text
[*] [Phase 1/4] Ingesting EVTX: samples\attack_sample.evtx
    [+] Extracted 4 Process Creation events (Event ID 1).

[*] [Phase 2/4] Constructing Execution Graph (DAG)...
    [+] Graph built with 6 nodes and 4 edges.

--- Reconstructed Process Tree ---
[Root] msiexec.exe (2080)
└── MSI4FFD.tmp (3680)
    Command: "C:\Windows\Installer\MSI4FFD.tmp"
    └── cmd.exe (2892)
        Command: cmd
        └── whoami.exe (1372)
            Command: whoami

[*] [Phase 3/4] Running LLM Triage via Gemini...
Title:       Reconnaissance via whoami executed by temporary installer
Verdict:     Malicious
Technique:   T1082 - System Information Discovery
Process:     cmd.exe
Indicators:  whoami, cmd.exe, MSI*.tmp

[*] [Phase 4/4] Generating Sigma Detection Rule...
[✓] Complete! Sigma rule saved to: rules/proc_creation_win_reconnaissance_via_whoami_executed_.yml
```

Generated Rule (rules/proc_creation_win_...yml):

```text
title: Reconnaissance via whoami executed by temporary installer
id: 5b4e3657-3f3c-44bf-a0bf-953e5e406214
status: experimental
description: A temporary executable spawned cmd.exe which executed whoami.exe.
references:
  - [https://attack.mitre.org/techniques/T1082/](https://attack.mitre.org/techniques/T1082/)
author: Autonomous Sysmon-Sigma Pipeline
date: 2026/09/15
tags:
  - attack.t1082
  - attack.execution
logsource:
  category: process_creation
  product: windows
detection:
  selection_process:
    Image|endswith: \cmd.exe
  selection_cli:
    CommandLine|contains:
      - whoami
      - cmd.exe
      - MSI*.tmp
  condition: selection_process and selection_cli
falsepositives:
  - Legitimate software installation routines
  - Administrative maintenance tasks
level: high
```
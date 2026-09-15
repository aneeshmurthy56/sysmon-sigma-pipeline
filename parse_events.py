import os
import xml.etree.ElementTree as ET
import Evtx.Evtx as evtx

EVTX_FILE = os.path.join("samples", "attack_sample.evtx")


def get_process_creation_events(file_path):
    events = []

    with evtx.Evtx(file_path) as log:
        for record in log.records():
            try:
                # Parse the raw XML log entry
                root = ET.fromstring(record.xml())

                # Check for Event ID 1
                event_id_elem = root.find("{*}System/{*}EventID")
                if event_id_elem is None or event_id_elem.text != "1":
                    continue

                # Extract EventData key-value pairs
                event_data = root.find("{*}EventData")
                if event_data is None:
                    continue

                data = {}
                for elem in event_data.findall("{*}Data"):
                    name = elem.get("Name")
                    if name:
                        data[name] = elem.text or ""

                events.append({
                    "UtcTime": data.get("UtcTime", ""),
                    "ProcessId": data.get("ProcessId", ""),
                    "Image": data.get("Image", ""),
                    "CommandLine": data.get("CommandLine", ""),
                    "ParentProcessId": data.get("ParentProcessId", ""),
                    "ParentImage": data.get("ParentImage", ""),
                    "ParentCommandLine": data.get("ParentCommandLine", ""),
                    "User": data.get("User", "")
                })
            except Exception:
                continue

    return events


if __name__ == "__main__":
    print(f"Reading: {EVTX_FILE}...")
    events = get_process_creation_events(EVTX_FILE)
    print(f"Extracted {len(events)} Process Creation (Event ID 1) events.\n")

    # Display the first 3 events
    for idx, event in enumerate(events[:3], 1):
        print(f"Event #{idx}:")
        print(f"  Parent:  {event['ParentImage']} (PID: {event['ParentProcessId']})")
        print(f"  Process: {event['Image']} (PID: {event['ProcessId']})")
        print(f"  Command: {event['CommandLine']}")
        print("-" * 70)
import json
import os
import ssl
import urllib.request

# Bypass local Windows SSL certificate validation
ssl_context = ssl._create_unverified_context()

os.makedirs("samples", exist_ok=True)
target_path = os.path.join("samples", "attack_sample.evtx")

api_url = "https://api.github.com/repos/sbousseaden/EVTX-ATTACK-SAMPLES/contents/Execution"
headers = {"User-Agent": "Mozilla/5.0"}

print("Querying EVTX-ATTACK-SAMPLES repository...")

try:
    req = urllib.request.Request(api_url, headers=headers)
    with urllib.request.urlopen(req, context=ssl_context) as resp:
        repo_files = json.loads(resp.read().decode())

    # Pick the first .evtx file in the Execution folder
    evtx_candidate = next(
        f for f in repo_files
        if f.get("name", "").lower().endswith(".evtx")
    )

    download_url = evtx_candidate["download_url"]
    file_name = evtx_candidate["name"]
    print(f"Discovered sample: {file_name}")
    print(f"Downloading from {download_url}...")

    download_req = urllib.request.Request(download_url, headers=headers)
    with urllib.request.urlopen(download_req, context=ssl_context) as response, open(target_path, "wb") as out_file:
        out_file.write(response.read())

    file_size = os.path.getsize(target_path)
    print(f"Successfully saved to {target_path} ({file_size:,} bytes)")

except Exception as e:
    print(f"Dynamic discovery failed: {e}")
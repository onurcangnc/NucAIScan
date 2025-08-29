import subprocess, json
from ffufai.core.logger import log

def run_nuclei_batch(target_file, selected_templates):
    cmd = ["nuclei", "-l", target_file, "-jsonl"]

    resolved = list(sorted(set(selected_templates or [])))
    if resolved:
        for t in resolved:
            cmd += ["-t", t]

    if not resolved or not any("/exposures/" in t for t in resolved):
        cmd += ["-t", "exposures/"]

    log("step", f"Running Nuclei with {len(resolved)} selected templates + fallback exposures/")

    result = subprocess.run(cmd, capture_output=True, text=True)

    findings = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            findings.append(json.loads(line))
        except json.JSONDecodeError:
            log("warning", f"Skipping invalid JSON line: {line[:80]}")
            continue

    log("success", f"Nuclei produced {len(findings)} findings")
    return findings

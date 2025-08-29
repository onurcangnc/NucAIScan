import subprocess, json, requests
from ffufai.core.logger import log

requests.packages.urllib3.disable_warnings()


def subfinder(domain: str):
    """
    Run subfinder and return list of subdomains
    """
    try:
        log("info", f"Running subfinder for {domain}...")
        cmd = f"subfinder -d {domain} -all -recursive"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        subs = result.stdout.strip().splitlines()
        return subs
    except Exception as e:
        log("error", f"Subfinder error: {e}")
        return []


def httpx_alive(domain: str):
    """
    Run httpx with SSL check disabled (-nc).
    Parse plain text output (fallback if JSONL not valid).
    """
    import subprocess, json, re

    try:
        result = subprocess.run(
            ["httpx", "-silent", "-nc", "-status-code"],
            input=domain,
            capture_output=True, text=True, timeout=15
        )

        output = result.stdout.strip()
        if not output:
            log("warning", f"httpx gave no output for {domain}")
            return None, None

        # Ex: "http://onurcangenc.com.tr [200]"
        match = re.match(r"(\S+)\s+\[(\d+)\]", output)
        if match:
            url = match.group(1)
            code = int(match.group(2))
            return url, code

        log("warning", f"Could not parse httpx output for {domain}: {output}")
        return None, None

    except Exception as e:
        log("error", f"httpx failed on {domain}: {e}")
        return None, None


def run_subzy(domain: str):
    """
    Run Subzy directly with subfinder output
    """
    try:
        log("info", f"Running Subzy for {domain} with subfinder output...")

        subs = subfinder(domain)
        if not subs:
            log("warning", f"No subdomains found for {domain}, skipping Subzy.")
            return None

        # Run subzy (send subs from stdin)
        cmd_subzy = "subzy --targets -"
        subzy = subprocess.run(
            cmd_subzy, shell=True, input="\n".join(subs),
            capture_output=True, text=True
        )
        return subzy.stdout

    except Exception as e:
        log("error", f"Subzy error: {e}")
        return None

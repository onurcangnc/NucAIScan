import subprocess, json
from collections import Counter
from ffufai.core.logger import log
from ffufai.core.utils import run

WORDLIST = "/usr/share/wordlists/onelistforallmicro.txt"


def ffuf_scan(url, jobid):
    """
    FFUF scan with warmup-based fw detection.

    Args:
        url (str): Target URL
        jobid (str/int): Job ID for temp file naming
    Returns:
        str: path to ffuf json output
    """
    tmpjson = f"/tmp/ffuf_raw_{jobid}.json"

    # 1) Warmup: All Status Codes
    warmup_json = f"/tmp/ffuf_warmup_{jobid}.json"
    cmd = (
        f"ffuf -u {url}/FUZZ -w {WORDLIST} "
        f"-of json -o {warmup_json} -mc all -s -timeout 5 -maxtime-job 1"
    )
    log("step", f"Warmup FFUF on {url} (-mc all)")
    subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # 2) Read first 50 results → wc values
    try:
        with open(warmup_json) as f:
            data = json.load(f)
        results = data.get("results", [])[:100]
        wc_values = [r.get("words") for r in results if r.get("words") is not None]

        if wc_values:
            fw_val = Counter(wc_values).most_common(1)[0][0]
            log("info", f"Selected fw={fw_val} from warmup (top 50)")
        else:
            log("warning", "No 200 responses found in warmup, default fw=0")
            fw_val = 0

    except Exception as e:
        log("error", f"Warmup parse failed: {e}")
        fw_val = 0

    # 3) Always match 200
    match_codes = "200"

    # 4) Main Scan
    cmd = (
        f"ffuf -u {url}/FUZZ -w {WORDLIST} "
        f"-of json -o {tmpjson} -mc {match_codes} -fw {fw_val} -s -timeout 5"
    )
    log("step", f"Running main FFUF with -mc {match_codes} -fw {fw_val}")
    subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    return tmpjson


def extract_filtered_paths(ffuf_json):
    """
    Parse FFUF JSON output and return discovered paths.
    Only keep 200 responses, and drop the most common wc cluster.
    """
    try:
        with open(ffuf_json, encoding="utf-8", errors="replace") as f:
            data = json.load(f)

        word_clusters = {}
        paths = []

        for r in data.get("results", []):
            fuzz_path = r["input"]["FUZZ"]
            status = r.get("status")

            if status == 200:
                wc = r.get("words") or 0
                word_clusters.setdefault(wc, []).append(fuzz_path)
                paths.append((fuzz_path, wc))

        if not paths:
            return []

        most_common_wc = max(word_clusters, key=lambda k: len(word_clusters[k]))
        filtered = [p for p, wc in paths if wc != most_common_wc]

        log("info", f"Filtered out {len(word_clusters[most_common_wc])} paths with wc={most_common_wc}")
        log("info", f"Retained {len(filtered)} unique-looking 200 paths after filtering.")

        return filtered

    except Exception as e:
        log("error", f"FFUF JSON parse error: {e}")
        return []


def grab_signals(url, ffuf_paths):
    """
    Detect tech signals from headers, body (truncated), and FFUF paths.
    Returns a dict for AI prompt generation.
    """
    signals = []

    # 1) Headers + Body
    try:
        res = run(f"curl -s -k -i {url} --max-time 8")
        raw = res.stdout.lower()

        parts = raw.split("\r\n\r\n", 1)
        headers = parts[0] if parts else raw
        body = parts[1] if len(parts) > 1 else ""
        body = body[:1500]

        # Header-based signals
        if "server: nginx" in headers:
            signals.append({"tech": "nginx", "source": "header"})
        if "server: apache" in headers:
            signals.append({"tech": "apache", "source": "header"})
        if "x-powered-by: express" in headers:
            signals.append({"tech": "expressjs", "source": "header"})
        if "x-aspnet-version" in headers or "asp.net" in headers:
            signals.append({"tech": "aspnet", "source": "header"})
        if "x-powered-by: php" in headers or "php/" in headers:
            signals.append({"tech": "php", "source": "header"})

        # Body-based signals
        if "__next_data__" in body:
            signals.append({"tech": "nextjs", "source": "body"})
        if "wp-content" in body:
            signals.append({"tech": "wordpress", "source": "body"})
        if "csrfmiddlewaretoken" in body:
            signals.append({"tech": "django", "source": "body"})
        if "laravel_session" in body:
            signals.append({"tech": "laravel", "source": "body"})
        if "react" in body and "root" in body:
            signals.append({"tech": "react", "source": "body"})

    except Exception as e:
        log("warning", f"Header grab failed for {url}: {e}")

    # 2) Path-based signals
    for path in ffuf_paths:
        if ".php" in path:
            signals.append({"tech": "php", "path": path})
        elif ".aspx" in path:
            signals.append({"tech": "aspnet", "path": path})
        elif "_next" in path:
            signals.append({"tech": "nextjs", "path": path})
        elif "wp-" in path or "xmlrpc.php" in path:
            signals.append({"tech": "wordpress", "path": path})
        elif "graphql" in path:
            signals.append({"tech": "graphql", "path": path})
        elif "swagger" in path or "openapi" in path:
            signals.append({"tech": "swagger_docs", "path": path})
        elif "phpmyadmin" in path:
            signals.append({"tech": "phpmyadmin", "path": path})

    return {
        "url": url,
        "signals": signals,
        "endpoints": ffuf_paths
    }

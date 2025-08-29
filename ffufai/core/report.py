import os, json, re
from urllib.parse import urlparse
from ffufai.core.logger import log
import openai

REPORTS_DIR = "./reports"
os.makedirs(REPORTS_DIR, exist_ok=True)

MODEL = os.getenv("FFUFAI_MODEL", "gpt-4.1-mini")
client = openai.OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

def generate_html_report(domain, subs, subzy, ffuf_data, nuclei_data):
    prompt = f"""
Generate only the <body> content (tables and sections) for a security report.

Target domain: {domain}

Subdomains:
{json.dumps(subs, indent=2)}

Subzy (takeover checks):
{subzy}

FFUF results:
{json.dumps(ffuf_data, indent=2)}

Nuclei results:
{json.dumps(nuclei_data, indent=2)}

Rules:
- Use <h2> for sections (Subdomains, FFUF, Nuclei, etc.)
- Use <table> for findings.
- Color rows by severity: critical=red, high=orange, medium=yellow, low=green.
- Do NOT include <html>, <head>, or <body> tags. I will wrap them myself.
    """

    try:
        resp = client.chat.completions.create(
            model=MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0
        )
        raw = resp.choices[0].message.content.strip()

        # sanitize (remove code fences if AI wrapped in ```html ... ```)
        if raw.startswith("```"):
            raw = re.sub(r"^```[a-zA-Z]*", "", raw)
            raw = raw.strip("` \n")

        # final HTML wrapper with CSS
        html = f"""
<html>
<head>
<meta charset="utf-8">
<title>Scan Report - {domain}</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 20px; }}
table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
th, td {{ border: 1px solid #ccc; padding: 8px; }}
th {{ background-color: #f2f2f2; }}
tr.critical {{ background-color: #ffcccc; }}
tr.high {{ background-color: #ffe0b3; }}
tr.medium {{ background-color: #ffffb3; }}
tr.low {{ background-color: #ccffcc; }}
</style>
</head>
<body>
<h1>DAST Scan Report for {domain}</h1>
{raw}
</body>
</html>
        """

        # --- ✅ Safe filename ---
        parsed = urlparse(domain)
        if parsed.netloc:
            outname = parsed.netloc
        else:
            outname = domain
        outname = outname.strip().lower()

        outpath = os.path.join(REPORTS_DIR, f"{outname}.html")

        with open(outpath, "w", encoding="utf-8") as f:
            f.write(html)

        log("ai", f"Report written to {outpath}")
        return outpath

    except Exception as e:
        log("error", f"AI Report Error: {e}")
        return None

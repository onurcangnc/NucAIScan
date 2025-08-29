import os, json, re
from ffufai.core.logger import log
from ffufai.core.utils import resolve_template_paths, ALL_TEMPLATES
import openai

# -------------------------
# Setup
# -------------------------
MODEL = os.getenv("FFUFAI_MODEL", "gpt-4.1-mini")
client = openai.OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# -------------------------
# Helpers
# -------------------------
def filter_candidates(signals):
    """Tech stack sinyallerine göre template filtrele (rel path match)."""
    signals = [s.lower() for s in signals]
    candidates = []

    for tmpl in ALL_TEMPLATES:
        low_rel = tmpl["rel"].lower()
        if any(sig in low_rel for sig in signals):
            candidates.append(tmpl["abs"])

    return list(set(candidates))

# -------------------------
# AI selection for signals
# -------------------------
def batch_select_nuclei_templates(candidates, tech_signals, backend=None, use_ai=False):
    """
    AI-assisted nuclei template selection.
    """
    selected = candidates[:]

    # 1) backend override filter
    if backend:
        log("step", f"Backend override = {backend}")
        selected = [t for t in candidates if backend.lower() in t.lower()]
        log("info", f"{len(selected)} candidates after backend filter")

    # 2) AI Integration
    if use_ai and selected:
        try:
            prompt = (
                "You are given the following Nuclei template filenames:\n"
                f"{json.dumps(selected)}\n\n"
                f"Detected stack/signals: {tech_signals}\n\n"
                "Select the most relevant templates. "
                "Return ONLY a JSON array of filenames, nothing else."
            )

            resp = client.chat.completions.create(
                model=MODEL,
                messages=[{"role": "user", "content": prompt}],
                temperature=0
            )
            raw = resp.choices[0].message.content.strip()

            # sanitize
            if raw.startswith("```"):
                raw = re.sub(r"^```[a-zA-Z]*", "", raw)
                raw = raw.strip("` \n")

            ai_selected = json.loads(raw)

            # sadece retrieve ones in the list
            selected = [t for t in selected if t in ai_selected]
            log("ai", f"AI reduced {len(candidates)} → {len(selected)} templates")

        except Exception as e:
            log("warning", f"AI parse error ({e}), fallback to {len(selected)} candidates")

    return selected

# -------------------------
# AI selection for backend override
# -------------------------
def filter_backend_templates(backend, candidates):
    prompt = (
        f"Backend technology: {backend}\n"
        f"Candidate Nuclei templates:\n" + "\n".join(candidates) + "\n\n"
        "Select the most relevant templates for scanning this backend, "
        "prioritizing high/critical issues and avoiding redundant detections. "
        "Return only a JSON array of filenames."
    )

    try:
        resp = client.chat.completions.create(
            model=MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0
        )
        raw = resp.choices[0].message.content.strip()

        # sanitize
        if raw.startswith("```"):
            raw = re.sub(r"^```[a-zA-Z]*", "", raw)
            raw = raw.strip("` \n")

        return json.loads(raw)
    except Exception as e:
        log("warning", f"AI filter_backend_templates error: {e}, fallback to all candidates")
        return candidates

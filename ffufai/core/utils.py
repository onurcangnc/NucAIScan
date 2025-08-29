import subprocess
import os
from pathlib import Path

# -------------------------
# Path Config
# -------------------------
CUSTOM_TEMPLATES_DIR = Path("/home/onurcan/ffufai/custom-templates")
NUCLEI_TEMPLATE_ROOT = Path.home() / ".local" / "nuclei-templates"

# -------------------------
# Subprocess Wrapper
# -------------------------
def run(cmd, capture_output=True):
    """
    Güvenli subprocess wrapper.
    stdout/stderr binary alınır ve utf-8 decode edilir,
    bozuk karakterler ignore edilir.
    """
    result = subprocess.run(
        cmd,
        shell=True,
        capture_output=capture_output,
        text=False
    )

    stdout = result.stdout.decode("utf-8", errors="ignore") if result.stdout else ""
    stderr = result.stderr.decode("utf-8", errors="ignore") if result.stderr else ""
    result.stdout, result.stderr = stdout, stderr
    return result

# -------------------------
# Upload All Templates
# -------------------------
def gather_all_templates():
    """Lokal tüm nuclei template dosyalarını bul (full + relative metadata)."""
    paths = []
    for base in [NUCLEI_TEMPLATE_ROOT, CUSTOM_TEMPLATES_DIR]:
        if base.exists():
            for p in base.rglob("*.yaml"):
                rel = str(p.relative_to(base))
                full = str(p)
                paths.append({
                    "rel": rel,   # AI selection
                    "abs": full   # for selector.py it was 'full' previously
                })
    return paths

ALL_TEMPLATES = gather_all_templates()

# -------------------------
# Normalize AI responses
# -------------------------
def resolve_template_paths(template_list):
    """AI’dan dönen template listelerini doğrula (full path'e çevir)."""
    resolved, not_found = [], []

    for t in template_list:
        
        if t.endswith("/"):
            resolved.append(t)
            continue

        
        for base in [NUCLEI_TEMPLATE_ROOT, Path("/root/.local/nuclei-templates"), CUSTOM_TEMPLATES_DIR]:
            try:
                t_path = Path(t)
                if t_path.is_absolute() and base in t_path.parents:
                    t = str(t_path.relative_to(base))  
                    break
            except:
                continue

        
        found = next((tmpl["abs"] for tmpl in ALL_TEMPLATES if tmpl["rel"] == t), None)

        if found:
            resolved.append(found)
        else:
            not_found.append(t)

    if not_found:
        print(f"[!]⚠️ Could not resolve templates: {not_found}")

    return resolved

# -------------------------
# Backend override
# -------------------------
def gather_templates_for_backend(keyword):
    """
    nuclei-templates altında backend keyword’ü geçen
    klasörleri ve .yaml dosyalarını topla.
    """
    matches = []
    for root, dirs, files in os.walk(str(NUCLEI_TEMPLATE_ROOT)):
        
        if keyword.lower() in root.lower():
            matches.append(root)
        
        for f in files:
            if f.endswith(".yaml") and keyword.lower() in f.lower():
                matches.append(os.path.join(root, f))

    
    if CUSTOM_TEMPLATES_DIR.exists():
        for p in CUSTOM_TEMPLATES_DIR.rglob("*.yaml"):
            if keyword.lower() in str(p).lower():
                matches.append(str(p))

    return matches

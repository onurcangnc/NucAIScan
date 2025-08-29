#!/usr/bin/env python3
import argparse, asyncio, time, re
from ffufai.core.logger import log
from ffufai.core.report import generate_html_report
from ffufai.scanners.subdomain import subfinder, httpx_alive, run_subzy
from ffufai.scanners.ffuf_handler import ffuf_scan, extract_filtered_paths, grab_signals
from ffufai.core.utils import resolve_template_paths
from ffufai.scanners.nuclei_handler import run_nuclei_batch
from ffufai.ai.selector import batch_select_nuclei_templates

SEM_LIMIT = 5

# -------------------------
# Helpers
# -------------------------
def is_direct_target(target: str) -> bool:
    if target.startswith("http://") or target.startswith("https://"):
        return True
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target):
        return True
    return False

async def ffuf_worker(url, idx, sem):
    async with sem:
        log("step", f"[{idx}] FFUF on {url}")
        start_time = time.time()
        j1_json = ffuf_scan(url, idx)
        raw_paths = extract_filtered_paths(j1_json) if j1_json else []
        duration = time.time() - start_time
        m, s = divmod(int(duration), 60)
        h, m = divmod(m, 60)
        log("success", f"{len(raw_paths)} paths for {url} (Duration: {h:01}:{m:02}:{s:02})")
        return url, raw_paths

async def nuclei_worker(target_file, templates, sem):
    async with sem:
        return run_nuclei_batch(target_file, templates)

# -------------------------
# Main Async Pipeline
# -------------------------
async def main_async(domain, args):
    log("step", f"[*] Starting scan for {domain}")

    # --- Subdomain Enumeration ---
    subs = subfinder(domain)
    if not subs:
        log("error", f"No subdomains found for {domain}")
        return
    log("success", f"{len(subs)} subdomains found.")

    # --- HTTPX Alive ---
    alive = []
    for sub in subs:
        url, code = httpx_alive(sub)
        if url:
            alive.append(url)
            log("success", f"[LIVE:{code}] {url}")
    if not alive:
        log("error", f"No live subdomains found for {domain}")
        return

    # --- Subzy ---
    subzy_out = run_subzy(domain)

    # --- FFUF Scanning (parallel) ---
    sem = asyncio.Semaphore(SEM_LIMIT)
    tasks = [ffuf_worker(url, i+1, sem) for i, url in enumerate(alive)]
    results = await asyncio.gather(*tasks)

    ffuf_results, all_paths = {}, []
    for url, paths in results:
        ffuf_results[url] = paths
        for p in paths:
            all_paths.append(f"{url.rstrip('/')}/{p.lstrip('/')}")

    alive_file = "/tmp/alive.txt"
    with open(alive_file, "w") as f:
        f.write("\n".join(alive))

    ffuf_paths_file = "/tmp/ffuf_paths.txt"
    with open(ffuf_paths_file, "w") as f:
        f.write("\n".join(set(all_paths)))

    # --- Template Selection ---
    if args.backend:
        from ffufai.core.utils import gather_templates_for_backend
        from ffufai.ai.selector import filter_backend_templates

        candidates = gather_templates_for_backend(args.backend)
        log("info", f"Backend override = {args.backend}, {len(candidates)} candidates found")

        try:
            selected_templates = filter_backend_templates(args.backend, candidates) if args.ai else candidates
            if args.ai:
                log("info", f"AI reduced {len(candidates)} → {len(selected_templates)} templates")
        except Exception as e:
            log("error", f"AI filter_backend_templates error: {e}, fallback to all candidates")
            selected_templates = candidates
    else:
        domain_infos, tech_signals = [], []
        for url in alive:
            di = grab_signals(url, ffuf_results.get(url, []))
            domain_infos.append(di)
            tech_signals.append(di.get("tech", []))

        selected_templates = batch_select_nuclei_templates(domain_infos, tech_signals, use_ai=args.ai)

        # normalize dict → str
        normalized = []
        for t in selected_templates:
            if isinstance(t, dict) and "template" in t:
                normalized.append(t["template"])
            elif isinstance(t, str):
                normalized.append(t)
        selected_templates = resolve_template_paths(normalized)

    for t in selected_templates:
        log("info", f"✔ Using: {t}")

    # --- Run Nuclei ---
    sem_nuclei = asyncio.Semaphore(SEM_LIMIT)
    tasks_nuclei = [
        nuclei_worker(alive_file, selected_templates, sem_nuclei),
        nuclei_worker(ffuf_paths_file, selected_templates, sem_nuclei),
    ]
    nuclei_findings_list = await asyncio.gather(*tasks_nuclei)
    nuclei_findings = sum(nuclei_findings_list, [])

    if not nuclei_findings:
        log("warning", "No findings from Nuclei.")
    else:
        log("success", f"Nuclei produced {len(nuclei_findings)} findings.")

    # --- Reporting ---
    generate_html_report(domain, subs, subzy_out, ffuf_results, nuclei_findings)
    log("step", f"Scan completed for {domain}")

# -------------------------
# Entrypoint
# -------------------------
def main():
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("domain", help="Target domain, full URL, or IP")
    parser.add_argument("--backend", help="Manually specify backend (php, next, etc.)")
    parser.add_argument("--ai", action="store_true", help="Use AI for Nuclei template selection")

    args = parser.parse_args()

    if is_direct_target(args.domain):
        log("step", f"[+] Direct mode detected for {args.domain}, skipping subfinder.")
        j1_json = ffuf_scan(args.domain, 1)
        paths = extract_filtered_paths(j1_json) if j1_json else []
        di = grab_signals(args.domain, paths)
        log("success", f"Direct mode finished, {len(paths)} paths discovered.")

        # --- Template Selection ---
        if args.backend:
            from ffufai.core.utils import gather_templates_for_backend
            from ffufai.ai.selector import filter_backend_templates

            candidates = gather_templates_for_backend(args.backend)
            log("info", f"Backend override = {args.backend}, {len(candidates)} candidates found")

            try:
                selected_templates = filter_backend_templates(args.backend, candidates) if args.ai else candidates
                if args.ai:
                    log("info", f"AI reduced {len(candidates)} → {len(selected_templates)} templates")
            except Exception as e:
                log("error", f"AI filter_backend_templates error: {e}, fallback to all candidates")
                selected_templates = candidates
        else:
            domain_infos = [di]
            tech_signals = [di.get("tech", [])]
            selected_templates = batch_select_nuclei_templates(domain_infos, tech_signals, use_ai=args.ai)

            normalized = []
            for t in selected_templates:
                if isinstance(t, dict) and "template" in t:
                    normalized.append(t["template"])
                elif isinstance(t, str):
                    normalized.append(t)
            selected_templates = resolve_template_paths(normalized)

        for t in selected_templates:
            log("info", f"✔ Using: {t}")

        # --- Run Nuclei in Direct Mode ---
        sem_nuclei = asyncio.Semaphore(SEM_LIMIT)
        alive_file = "/tmp/alive.txt"
        with open(alive_file, "w") as f:
            f.write(args.domain + "\n")
        ffuf_paths_file = "/tmp/ffuf_paths.txt"
        with open(ffuf_paths_file, "w") as f:
            f.write("\n".join(paths))

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        results = loop.run_until_complete(asyncio.gather(
            nuclei_worker(alive_file, selected_templates, sem_nuclei),
            nuclei_worker(ffuf_paths_file, selected_templates, sem_nuclei),
        ))
        nuclei_findings = sum(results, [])
        if not nuclei_findings:
            log("warning", "No findings from Nuclei (direct mode).")
        else:
            log("success", f"Nuclei produced {len(nuclei_findings)} findings (direct mode).")

        # --- Reporting (Direct Mode) ---
        generate_html_report(
            args.domain,            # domain
            [args.domain],          # subs (sadece target)
            None,                   # subzy (direct modda yok)
            {args.domain: paths},   # ffuf_data
            nuclei_findings         # nuclei_data
        )
        log("step", f"Direct mode scan completed for {args.domain}")

    else:
        asyncio.run(main_async(args.domain, args))

if __name__ == "__main__":
    main()

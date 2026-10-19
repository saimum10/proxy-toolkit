"""Export helpers. All functions take a list of ProxyResult in the order to be written."""
from __future__ import annotations

import csv
import json
import re
from collections import defaultdict
from pathlib import Path

CSV_FIELDS = ["proxy", "url", "type", "live", "exit_ip", "country", "country_code", "city",
              "anonymity", "remote_dns", "latency_ms", "stability", "score", "targets",
              "network", "isp", "error"]


def _row(r) -> dict:
    return {
        "proxy": r.address,
        "url": r.url,
        "type": r.proto,
        "live": r.live,
        "exit_ip": r.exit_ip,
        "country": r.country,
        "country_code": r.country_code,
        "city": r.city,
        "anonymity": r.anonymity,
        "remote_dns": r.remote_dns,
        "latency_ms": round(r.latency_ms) if r.latency_ms is not None else None,
        "stability": f"{r.passed}/{r.rounds}" if r.rounds else "",
        "score": r.score if r.live else None,
        "targets": r.targets,
        "network": r.net_type,
        "isp": r.isp,
        "error": r.error,
    }


def export_json(results, path) -> int:
    rows = [_row(r) for r in results]
    Path(path).write_text(json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8")
    return len(rows)


def export_csv(results, path) -> int:
    n = 0
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
        w.writeheader()
        for r in results:
            row = _row(r)
            row["targets"] = " ".join(f"{k}:{'ok' if v else 'fail'}" for k, v in r.targets.items())
            w.writerow(row)
            n += 1
    return n


def export_txt(results, path) -> int:
    """One working proxy URL per line (live only)."""
    urls = [r.url for r in results if r.live]
    Path(path).write_text("\n".join(urls) + ("\n" if urls else ""), encoding="utf-8")
    return len(urls)


def export_by_country(results, folder) -> int:
    """Write <CC>.txt per country (live only) plus all_live.txt. Returns number of files."""
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    groups = defaultdict(list)
    for r in results:
        if r.live:
            cc = re.sub(r"[^A-Za-z0-9]", "", r.country_code) or "unknown"
            groups[cc.upper()].append(r.url)
    for cc, urls in groups.items():
        (folder / f"{cc}.txt").write_text("\n".join(urls) + "\n", encoding="utf-8")
    all_urls = [u for urls in groups.values() for u in urls]
    (folder / "all_live.txt").write_text("\n".join(all_urls) + ("\n" if all_urls else ""),
                                          encoding="utf-8")
    return len(groups) + 1

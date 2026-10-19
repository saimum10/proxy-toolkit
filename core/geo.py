"""Country / city / ISP lookup for exit IPs via ip-api.com (batch endpoint).

The lookup is made directly from your machine (NOT through the proxies).
Free tier: plain HTTP only, 15 batch requests per minute (100 IPs each), non-commercial use.
"""
from __future__ import annotations

import asyncio
from typing import Callable

import aiohttp

GEO_URL = "http://ip-api.com/batch"
FIELDS = "status,country,countryCode,city,isp,hosting,mobile,query"


async def _sleep(seconds: float, should_stop: Callable[[], bool]) -> None:
    end = asyncio.get_running_loop().time() + seconds
    while not should_stop() and asyncio.get_running_loop().time() < end:
        await asyncio.sleep(0.5)


async def lookup(ips, should_stop: Callable[[], bool] = lambda: False,
                 log: Callable[[str], None] = lambda m: None) -> dict:
    """Return {ip: info-dict} for every IP that could be resolved."""
    out: dict = {}
    ips = list(dict.fromkeys(ips))
    timeout = aiohttp.ClientTimeout(total=20)
    async with aiohttp.ClientSession(timeout=timeout, trust_env=False) as s:
        for i in range(0, len(ips), 100):
            batch = ips[i:i + 100]
            payload = [{"query": ip, "fields": FIELDS} for ip in batch]
            for _ in range(3):
                if should_stop():
                    return out
                try:
                    async with s.post(GEO_URL, json=payload) as r:
                        if r.status == 429:
                            wait = int(r.headers.get("X-Ttl", "60")) + 1
                            log(f"Geo lookup rate-limited, waiting {wait}s…")
                            await _sleep(wait, should_stop)
                            continue
                        data = await r.json(content_type=None)
                        remaining = r.headers.get("X-Rl")
                        ttl = r.headers.get("X-Ttl")
                    for item in data:
                        if isinstance(item, dict) and item.get("status") == "success":
                            out[item.get("query")] = item
                    if remaining == "0":
                        await _sleep(int(ttl or 5) + 1, should_stop)
                    break
                except Exception as e:
                    log(f"Geo lookup error: {type(e).__name__}")
                    await _sleep(2, should_stop)
    return out


def apply(results, info: dict) -> None:
    """Copy lookup data from `info` ({ip: dict}) onto ProxyResult objects (matched by exit IP)."""
    for r in results:
        i = info.get(r.exit_ip)
        if not i:
            continue
        r.country = i.get("country", "") or ""
        r.country_code = i.get("countryCode", "") or r.country_code
        r.city = i.get("city", "") or ""
        r.isp = i.get("isp", "") or ""
        r.net_type = "Datacenter" if i.get("hosting") else ("Mobile" if i.get("mobile") else "ISP")

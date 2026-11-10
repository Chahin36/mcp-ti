import os
from .base import Connector
from datetime import datetime, timezone

PATHS = {"hash": "files", "domain": "domains", "ip": "ip_addresses"}

class VirusTotal(Connector):
    name = "VirusTotal"
    supports = {"hash", "domain", "ip"}

    async def query(self, client, ioc):
        r = await client.get(
            f"https://www.virustotal.com/api/v3/{PATHS[ioc.type]}/{ioc.value}",
            headers={"x-apikey": os.environ["VT_API_KEY"]},
        )
        r.raise_for_status()
        a = r.json()["data"]["attributes"]
        s = a.get("last_analysis_stats", {})
        ts = a.get("last_analysis_date")
        return {
            "malicious": s.get("malicious", 0),
            "suspicious": s.get("suspicious", 0),
            "harmless": s.get("harmless", 0),
            "undetected": s.get("undetected", 0),
            "reputation": a.get("reputation"),
            "categories": sorted(set((a.get("categories") or {}).values()))[:10],
            "last_analysis_date": (
                datetime.fromtimestamp(ts, timezone.utc).isoformat() if ts else None
            ),
        }

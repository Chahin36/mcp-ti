import os
from .base import Connector

class AbuseIPDB(Connector):
    name = "AbuseIPDB"
    supports = {"ip"}
    MAX_AGE = 90

    async def query(self, client, ioc):
        r = await client.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": os.environ["ABUSEIPDB_API_KEY"], "Accept": "application/json"},
            params={"ipAddress": ioc.value, "maxAgeInDays": self.MAX_AGE},
        )
        r.raise_for_status()
        d = r.json()["data"]
        return {
            "abuse_score": d["abuseConfidenceScore"],
            "total_reports": d["totalReports"],
            "distinct_reporters": d.get("numDistinctUsers"),
            "is_whitelisted": d.get("isWhitelisted"),
            "is_tor": d.get("isTor"),
            "usage_type": d.get("usageType"),
            "isp": d.get("isp"),
            "country": d.get("countryCode"),
            "last_reported": d.get("lastReportedAt"),
            "max_age_days": self.MAX_AGE,
        }

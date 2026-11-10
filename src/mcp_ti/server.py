import asyncio, ipaddress, re
import httpx
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP
from .models import IOC
from .connectors.abuseipdb import AbuseIPDB
from .connectors.virustotal import VirusTotal
from .engine.scoring import assess

load_dotenv()
mcp = FastMCP("threat-intel")
CONNECTORS = [AbuseIPDB(), VirusTotal()]     # add MISP here later (NFR-003)

HASH_RE = re.compile(r"^([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$")

async def investigate(ioc: IOC) -> dict:
    sources = [c for c in CONNECTORS if ioc.type in c.supports]
    async with httpx.AsyncClient(timeout=10) as client:
        results = await asyncio.gather(*(c.lookup(client, ioc) for c in sources))
    dumped = [r.model_dump() for r in results]
    return {"ioc": ioc.model_dump(), "sources": dumped, "assessment": assess(dumped)}
@mcp.tool()
async def lookup_ip(ip: str) -> dict:
    """Investigate an IPv4/IPv6 address across all configured sources."""
    try:
        value = str(ipaddress.ip_address(ip.strip()))
    except ValueError:
        return {"error": "invalid_ip", "input": ip}
    return await investigate(IOC(value=value, type="ip"))

@mcp.tool()
async def lookup_domain(domain: str) -> dict:
    """Investigate a domain name across all configured sources."""
    d = domain.strip().lower()
    if not DOMAIN_RE.match(d):
        return {"error": "invalid_domain", "input": domain}
    return await investigate(IOC(value=d, type="domain"))

@mcp.tool()
async def lookup_hash(file_hash: str) -> dict:
    """Investigate a file hash (MD5, SHA-1 or SHA-256) across all configured sources."""
    h = file_hash.strip().lower()
    if not HASH_RE.match(h):
        return {"error": "invalid_hash", "input": file_hash}
    return await investigate(IOC(value=h, type="hash"))

if __name__ == "__main__":
    mcp.run()

from abc import ABC, abstractmethod
from datetime import datetime, timezone
import httpx
from ..models import IOC, SourceResult

class Connector(ABC):
    name: str
    supports: set[str]

    @abstractmethod
    async def query(self, client: httpx.AsyncClient, ioc: IOC) -> dict: ...

    async def lookup(self, client: httpx.AsyncClient, ioc: IOC) -> SourceResult:
        now = datetime.now(timezone.utc).isoformat()
        try:
            data = await self.query(client, ioc)
            return SourceResult(name=self.name, status="ok", data=data, retrieved_at=now)
        except httpx.HTTPStatusError as e:
            code = e.response.status_code
            status = "not_found" if code == 404 else "rate_limited" if code == 429 else "error"
            return SourceResult(name=self.name, status=status, detail=f"HTTP {code}", retrieved_at=now)
        except Exception as e:     # never leak keys or raw exception text
            return SourceResult(name=self.name, status="error", detail=type(e).__name__, retrieved_at=now)

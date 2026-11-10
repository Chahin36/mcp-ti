from typing import Any, Literal
from pydantic import BaseModel

class IOC(BaseModel):
    value: str
    type: Literal["ip", "domain", "hash"]

class SourceResult(BaseModel):
    name: str
    status: Literal["ok", "not_found", "rate_limited", "error"]
    detail: str | None = None
    data: dict[str, Any] = {}
    retrieved_at: str          # UTC, ISO format (provenance)

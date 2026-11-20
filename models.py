from pydantic import BaseModel, Field
from typing import Optional


class ScanRequest(BaseModel):
    target: str = Field(..., min_length=1)
    authorized: bool = False
    profile: str = "safe"


class NmapRequest(BaseModel):
    command: str = Field(..., min_length=1)
    authorized: bool = False


class ScanResponse(BaseModel):
    scan_id: str
    status: str
    target: Optional[str] = None
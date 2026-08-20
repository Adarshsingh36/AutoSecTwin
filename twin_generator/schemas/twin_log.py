"""
Pydantic schemas for twin_logs.

Log entries are written internally by the Twin Orchestrator/engines and
are read-only from the API's perspective, so only a Read schema is needed.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict

from twin_generator.utils.enums import TwinLogEvent


class TwinLogRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    twin_id: int
    timestamp: datetime
    event: TwinLogEvent
    details: Optional[str]

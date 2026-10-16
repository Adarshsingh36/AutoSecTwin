# models.py
from pydantic import BaseModel
from typing import Optional
from sqlalchemy import Column, Integer, String, Float, Boolean
from database import Base

# --- SQLAlchemy Model (For the PostgreSQL Database) ---
class DBVulnerabilityRecord(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True) # finding_id primary key[cite: 1]
    cve_id = Column(String, index=True)
    title = Column(String)
    description = Column(String)
    service = Column(String)
    port = Column(Integer)
    host = Column(String)
    cvss_score = Column(Float, nullable=True)           # optional, informational only[cite: 1]
    exploitability_score = Column(Float, nullable=True) # populated by classifier[cite: 1]
    confidence_score = Column(Float, nullable=True)     # populated by Confidence Engine[cite: 1]
    is_legacy_flagged = Column(Boolean, default=False)  # populated by Legacy Profiler[cite: 1]
    hallucination_flag = Column(Boolean, default=False) # populated by Trust & Validation[cite: 1]
    pipeline_status = Column(String, default="scanned") # ensures frontend and orchestrator agree on state[cite: 1]

# --- Pydantic Model (For the API Data Passing) ---
class VulnerabilityRecord(BaseModel):
    cve_id: str
    title: str
    description: str
    service: str
    port: int
    host: str
    pipeline_status: str = "scanned"
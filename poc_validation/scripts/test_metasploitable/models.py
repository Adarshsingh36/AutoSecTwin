from sqlalchemy import Column, Integer, String
from database import Base
from pydantic import BaseModel

class DBVulnerabilityRecord(Base):
    __tablename__ = "vulnerabilities"
    
    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String, index=True)
    title = Column(String)
    description = Column(String)
    service = Column(String)
    port = Column(Integer)
    host = Column(String)
    pipeline_status = Column(String)

class VulnerabilityRecord(BaseModel):
    cve_id: str
    title: str
    description: str
    service: str
    port: int
    host: str
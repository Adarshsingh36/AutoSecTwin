from sqlalchemy import Column, DateTime, Float, Integer, JSON, String, Text
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from database.base import Base

from sqlalchemy import Column, DateTime, Float, Integer, JSON, String, Text
...

class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)

    name = Column(String(255), nullable=False)
    asset_type = Column(String(80), nullable=False)

    owner = Column(String(120), nullable=True)

    # Existing
    environment = Column(String(80), nullable=True)

    # -------- NEW --------

    hostname = Column(String(255), nullable=True)

    ip_address = Column(String(45), nullable=True)

    operating_system = Column(String(120), nullable=True)

    software = Column(String(255), nullable=True)

    version = Column(String(120), nullable=True)

    # ---------------------

    exposure = Column(Float, default=0.0, nullable=False)

    criticality = Column(Float, default=0.0, nullable=False)

    description = Column(Text, nullable=True)

    metadata_json = Column(JSON, nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    vulnerabilities = relationship("Vulnerability", back_populates="asset")
    twins = relationship("Twin", back_populates="asset")

    
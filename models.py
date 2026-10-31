from datetime import datetime
from sqlalchemy import (
    BigInteger, Column, DateTime, ForeignKey, Index, SmallInteger, String, Text,
    func,
)
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    pass


class Case(Base):
    """A grouping of related alerts. One case per (agent, threat_type) for now —
    that's the simplest defensible rule; swap in a real correlation engine later."""
    __tablename__ = "cases"

    id            = Column(BigInteger, primary_key=True, autoincrement=True)
    status        = Column(String(32), nullable=False, default="open")   # open|triaged|closed
    severity      = Column(SmallInteger, nullable=False, default=0)      # max rule_level
    threat_type   = Column(String(128))
    agent_name    = Column(String(128), index=True)
    first_seen    = Column(DateTime(timezone=True), nullable=False)
    last_seen     = Column(DateTime(timezone=True), nullable=False)
    alert_count   = Column(BigInteger, nullable=False, default=0)
    created_at    = Column(DateTime(timezone=True), server_default=func.now())
    updated_at    = Column(DateTime(timezone=True), server_default=func.now(),
                           onupdate=func.now())

    alerts = relationship("CaseAlert", back_populates="case",
                          cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_cases_open", "status", "last_seen",
              postgresql_where=(status == "open")),
    )


class CaseAlert(Base):
    """Immutable record of each alert ingested into a case. The UNIQUE
    wazuh_event_id makes re-polling safe."""
    __tablename__ = "case_alerts"

    id              = Column(BigInteger, primary_key=True, autoincrement=True)
    case_id         = Column(BigInteger, ForeignKey("cases.id", ondelete="CASCADE"),
                             nullable=False, index=True)
    wazuh_event_id  = Column(BigInteger, nullable=False, unique=True)  # from /api/v1/alerts

    event_time      = Column(DateTime(timezone=True), nullable=False)
    rule_id         = Column(String(32))
    rule_level      = Column(SmallInteger)
    description     = Column(Text)
    mitre_id        = Column(String(16))
    agent_name      = Column(String(128))
    agent_ip        = Column(INET)
    source_ip       = Column(INET)
    target_user     = Column(String(256))
    threat_type     = Column(String(128))
    raw_alert       = Column(JSONB, nullable=False)   # keep the exact JSON M2 received
    ingested_at     = Column(DateTime(timezone=True), server_default=func.now())

    case = relationship("Case", back_populates="alerts")

    __table_args__ = (
        Index("ix_case_alerts_event_time", "event_time"),
    )
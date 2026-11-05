from datetime import datetime

from sqlalchemy import DateTime, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(primary_key=True)
    # sha256(scanner|asset|plugin_id) -> the dedup key
    fingerprint: Mapped[str] = mapped_column(String(64), unique=True)
    scanner: Mapped[str] = mapped_column(String(50))
    asset: Mapped[str] = mapped_column(String(255), index=True)
    plugin_id: Mapped[str] = mapped_column(String(100))
    title: Mapped[str] = mapped_column(String(500))
    severity: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(16), default="open")
    cve: Mapped[str | None] = mapped_column(String(32), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    fixed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        # Most common dashboard query: "open criticals/highs"
        Index("ix_findings_status_severity", "status", "severity"),
    )

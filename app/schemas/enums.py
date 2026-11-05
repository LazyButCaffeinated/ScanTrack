from enum import Enum


class Role(str, Enum):
    admin = "admin"
    analyst = "analyst"
    viewer = "viewer"


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class Status(str, Enum):
    open = "open"
    in_progress = "in_progress"
    fixed = "fixed"

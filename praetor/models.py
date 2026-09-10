from enum import Enum

class Severity(int, Enum):
    INFO=0
    LOW=1
    MEDIUM=2
    HIGH=3
    CRITICAL=4

    @property
    def label(self) -> str:
        # every Enum member has a .name attribute. It's uppercase.
        return self.name.lower()

    @classmethod
    def from_any(cls, value) -> "Severity":
        if isinstance(value, cls):
            return value
        if isinstance(value, (int,float)):
            number=max(0, min(4, int(value)))
            return cls(number)
        text = str(value).strip().lower()
        table = {
            "critical": cls.CRITICAL,
            "severe": cls.CRITICAL,
            "emergency": cls.CRITICAL,
            "high": cls.HIGH,
            "major": cls.HIGH,
            "error": cls.HIGH,
            "medium": cls.MEDIUM,
            "moderate": cls.MEDIUM,
            "warning": cls.MEDIUM,
            "low": cls.LOW,
            "minor": cls.LOW,
            "info": cls.INFO,
            "informational": cls.INFO,
            "notice": cls.INFO,
        }
        return table.get(text, cls.MEDIUM)

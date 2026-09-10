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
       
        return _WORDS.get(text, cls.MEDIUM)
_WORDS = {
        "critical": Severity.CRITICAL,
        "severe": Severity.CRITICAL,
        "emergency": Severity.CRITICAL,
        "high": Severity.HIGH,
        "major": Severity.HIGH,
        "error": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "moderate": Severity.MEDIUM,
        "warning": Severity.MEDIUM,
        "low": Severity.LOW,
        "minor": Severity.LOW,
        "info": Severity.INFO,
        "informational": Severity.INFO,
        "notice": Severity.INFO,
}

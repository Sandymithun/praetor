from enum import Enum
from dataclasses import dataclass


class ObservableType(str, Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    SHA256 = "sha256"
    SHA1 = "sha1"
    MD5 = "md5"
    EMAIL = "email"
    USERNAME = "username"
    FILE_PATH = "file_path"
    HOSTNAME = "hostname"

    @property
    def is_hash(self) -> bool:
        return self in {ObservableType.SHA256, ObservableType.SHA1, ObservableType.MD5}

    @property
    def is_network(self) -> bool:
        return self in {ObservableType.IPV4, ObservableType.IPV6,
                        ObservableType.DOMAIN, ObservableType.URL}

@dataclass(frozen=True)
class Observable:
    """One indicator: a type, a value, and where it came from."""

    type: ObservableType
    value: str
    field: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "value", self.value.strip())

    def key(self) -> str:
        return f"{self.type.value}:{self.value.lower()}"

    def __str__(self) -> str:
        return f"{self.type.value}={self.value}"
from dataclasses import dataclass, field


@dataclass
class HttpSettings:
    timeout: float = 10.0
    follow_redirects: bool = True
    user_agent: str = "M-Hunter/0.1.0"

    def __post_init__(self):
        if self.timeout <= 0:
            raise ValueError("timeout must be greater than 0")

        if not self.user_agent.strip():
            raise ValueError("user_agent must not be empty")


@dataclass
class ScanSettings:
    auto_discover_scanners: bool = True


@dataclass
class Settings:
    http: HttpSettings = field(default_factory=HttpSettings)
    scan: ScanSettings = field(default_factory=ScanSettings)

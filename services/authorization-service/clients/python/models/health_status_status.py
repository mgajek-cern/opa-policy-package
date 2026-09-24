from enum import StrEnum


class HealthStatusStatus(StrEnum):
    OK = "ok"

    def __str__(self) -> str:
        return str(self.value)

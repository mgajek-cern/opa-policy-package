from enum import StrEnum


class DidType(StrEnum):
    CONTAINER = "container"
    DATASET = "dataset"
    FILE = "file"

    def __str__(self) -> str:
        return str(self.value)

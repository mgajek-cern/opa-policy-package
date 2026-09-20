from enum import StrEnum

class SubjectType(StrEnum):
    OIDC_SUBJECT = "oidc_subject"
    RUCIO_ACCOUNT = "rucio_account"

    def __str__(self) -> str:
        return str(self.value)

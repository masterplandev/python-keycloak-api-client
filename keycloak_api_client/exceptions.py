from typing import Any


class KeycloakApiClientException(Exception):
    def __init__(self, details: dict[str, Any]) -> None:
        super().__init__(details)
        self.details = details

    def __str__(self) -> str:
        return f"{self.__class__.__name__}: {self.details}"

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(details={self.details!r})"

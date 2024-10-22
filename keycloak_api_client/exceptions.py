class KeycloakApiClientException(Exception):
    pass


class LogoutFailed(Exception):
    pass


class RefreshTokenExpired(Exception):
    pass

# Python Keycloak API client

[![PyPI version](https://badge.fury.io/py/python-keycloak-api-client.svg)](https://badge.fury.io/py/python-keycloak-api-client) [![CircleCI](https://dl.circleci.com/status-badge/img/gh/masterplandev/python-keycloak-api-client/tree/main.svg?style=shield)](https://dl.circleci.com/status-badge/redirect/gh/masterplandev/python-keycloak-api-client/tree/main)

This library wraps the Keycloak REST API, providing an easy way to manage users, clients, and other Keycloak resources. It’s simple, extendable, and has been tested in production.

## Usage

### Install

```bash
$ pip install python-keycloak-api-client
```

### Example

```python
from keycloak_api_client import KeycloakApiClient

client = KeycloakApiClient(
    keycloak_url: "https://auth.myservice.com",
    realm: "myservice",
    admin_username: "my_keycloak_admin",
    admin_password: "...",
    admin_client_id: "my_service_backend_client_id",
    admin_client_secret: "...",
    relative_path: "/auth",
)

read_kc_user = client.get_keycloak_user_by_email('johndoe@myservice.com')
read_kc_user.email      # johndoe@myservice.com
read_kc_user.enabled    # True
read_kc_user.first_name # John
read_kc_user.last_name  # Doe
...
```

## Development

### Test

```bash
# Run linter and tests for all Python versions
$ tox
```

### Linter

```bash
# Format
$ ruff format

# Check
$ ruff check
```

### Install

```bash
$ pip install -e .
```

## Changelog

[CHANGELOG](CHANGELOG.md)

## License

[MIT](LICENSE)

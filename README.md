# Python Keycloak Client

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
    token_exchange_target_client_id: "my_service_backend_client_id",
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

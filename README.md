# Python Keycloak Client

## Usage

```python
from keycloak_api_client import KeycloakApiClient

keycloak_api_client = KeycloakApiClient(...)
read_keycloak_user = keycloak_api_client.get_keycloak_user_by_email('johndoe@example.com')
```

## Test

```bash
$ tox
```

## Development

```bash
$ pip install -e .
```

## Changelog

[CHANGELOG](CHANGELOG.md)

## License

[MIT](LICENSE)

# Python Keycloak Client

## Usage

```python
from keycloak_api_client import KeycloakApiClient

keycloak_api_client = KeycloakApiClient(...)
read_keycloak_user = keycloak_api_client.get_keycloak_user()
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

### v0.2.0
- Added option for custom read user output from get 
  and search user endpoints
- Fixed typo

### v0.1.0
- Initial release

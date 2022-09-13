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

### v0.4.0
- Added method `reset_password`

### v0.3.0
- Added method `count_users`

### v0.2.2
- Added `limit` and `offset` params in `KeycloakApiClient.search_users()` to control paging

### v0.2.1
- Fixed `StopIteration` when downloading user by email in case email partially matches found users but not exact match exact email 

### v0.2.0
- Method `get_keycloak_user` was replaced by `get_keycloak_user_by_id` and `get_keycloak_user_by_email`

### v0.1.1
- Fixed typo

### v0.1.0
- Initial release

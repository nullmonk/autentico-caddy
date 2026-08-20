# Autentico Features

- **oidc**: Requires an OIDC client to be registered in ACO.
  - Endpoints: `/admin/api/clients:POST`, `/admin/api/clients/{id}:GET`, `/admin/api/clients/{id}:PUT`
- **tls**: Will be enabled in the future to use ACO for issuing server certs.
  - Endpoints: N/A
- **mtls**: Requires the CA key to be installed.
  - Endpoints: `/ca.crt:GET` (Does not require API token)
- **groups**: Requires user and group lookups from the API.
  - Endpoints: `/admin/api/users/lookup:POST`

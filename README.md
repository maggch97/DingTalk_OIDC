# DingTalk -> OIDC Bridge (Minimal)

This service provides a minimal OpenID Connect layer in front of DingTalk. It performs the standard Authorization Code flow (browser redirect -> DingTalk -> callback -> OIDC code -> token) and issues an ID Token containing basic DingTalk user info. A UserInfo endpoint is now available.

## Features
- Standard OIDC Authorization Code flow (no custom `dt_code` param needed by client).
- `/authorize` starts flow and redirects user to DingTalk.
- `/dingtalk/callback` (internal) receives DingTalk `code` and creates OIDC authorization code.
- `/token` exchanges OIDC authorization code for ID Token (reused as access token).
- `/userinfo` returns profile claims extracted from the token (sub, name, email, phone_number if present).
- Discovery: `/.well-known/openid-configuration` with `userinfo_endpoint` + `/jwks.json` for keys.
- ID Token claims: `iss, sub, aud, exp, iat, nonce (if provided), name, email, phone_number`.
- In‑memory auth code + pending state stores (5/10 min TTL) and ephemeral RSA key.

## NOT Production Ready
- No TLS termination (use a reverse proxy or enable TLS yourself).
- Single client (configured by env).
- Ephemeral signing key (losing continuity for long‑lived sessions).
- No refresh tokens / no userinfo endpoint yet.
- Auth codes & tokens only in memory; not horizontally scalable.
- Random generators for auth codes are not cryptographically strong.

## Environment Variables
| Variable | Description |
|----------|-------------|
| `ISSUER` | Public base URL of this service (e.g. `https://oidc.example.com`). |
| `DINGTALK_CLIENT_ID` | DingTalk App Key. |
| `DINGTALK_CLIENT_SECRET` | DingTalk App Secret. |
| `ADDRESS` | (Optional) Listen address, default `:8080`. |

## Flow Diagram
```
Client Browser --> /authorize (OIDC)
	OIDC -> redirect to DingTalk authorize
	User logs in DingTalk
DingTalk -> /dingtalk/callback (OIDC) with code
	OIDC exchanges DingTalk code -> user info -> issues OIDC auth code
OIDC -> redirect back to client with code
Client -> /token -> ID Token (+ access token same value)
Client -> /userinfo (optional) with Bearer token
```

## Example Authorize Request
```
GET /authorize?client_id=YOUR_CLIENT_ID&redirect_uri=https://app.example.com/cb&response_type=code&scope=openid%20email%20profile&state=xyz&nonce=abc
```

## Example Token Request
```
POST /token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=RETURNED_CODE&client_id=YOUR_CLIENT_ID&client_secret=YOUR_SECRET
```

## Running
```bash
export ISSUER="http://localhost:8080"
export DINGTALK_CLIENT_ID="your_dt_app_key"
export DINGTALK_CLIENT_SECRET="your_dt_app_secret"
go run ./cmd/server
```

Then visit:
- Discovery: `http://localhost:8080/.well-known/openid-configuration`
- UserInfo (example):
	```bash
	curl -H "Authorization: Bearer <ID_TOKEN>" http://localhost:8080/userinfo
	```

## Next Steps / Ideas
- Add cryptographically secure auth code + nonce generation (`crypto/rand`).
- Persist signing key & rotation strategy.
- (DONE) Add `/userinfo` endpoint.
- Support Refresh Tokens.
- Multi-client registration + dynamic client metadata.
- Optional login UI if dt_code not supplied.
- Structured logging & metrics.

---
Generated initial minimal implementation. Improve as needed for production.

# Demo Auth

A small, local authentication/authorization demo project for experimenting with auth flows, permissions, and related logic. The codebase is intentionally minimal to keep focus on core auth behavior.

## Disclaimer

This project was vibecoded. Vibe-coding an authentication/authorization system is a horrible idea. Treat this code as a learning artifact, not production-ready security software.


## What’s Inside

- TypeScript project structure
- Zero runtime dependencies (Node built-ins only; TypeScript is dev-only)
- Source code under `src/`
- HTTP flow examples under `test/test.http`
- Standard Node tooling via `package.json`

## Implemented Protocols (Partial)

- OAuth 2.0 Authorization Code Grant (RFC 6749)
- PKCE for public clients (RFC 7636)
- Refresh Token grant (RFC 6749)
- OAuth 2.0 Token Exchange (RFC 8693)
- Bearer token usage (RFC 6750) for the `token_type`
- JWT access tokens (RFC 7519) with JWS RS256 signatures (RFC 7515)
- JWK/JWKS publishing for the signing key (RFC 7517)
- OIDC Discovery document at `/.well-known/openid-configuration` (OpenID Connect Discovery 1.0)
- ID Token issuance when `openid` scope is requested (OpenID Connect Core 1.0)

## Getting Started

1. Install dependencies:

```sh
npm install
```

2. Build and run the server:

```sh
npm run build
npm run start
```

3. Or run in dev mode with inspector:

```sh
npm run dev
```


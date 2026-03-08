# quarkus-dpop-demo

A companion project for the article [DPoP: Because Bearer Tokens Are Not Enough](../article.md). It demonstrates how to secure a Quarkus REST API with DPoP (Demonstration of Proof-of-Possession) as defined in [RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449).

## What it covers

- DPoP-bound token validation via Quarkus OIDC (`quarkus.oidc.token.authorization-scheme=dpop`)
- `jti` replay protection with a custom `@ServerRequestFilter`
- A k6 test script that exercises happy-path, replay attack, method mismatch, and URL mismatch scenarios

## Requirements

- Java 21+
- Maven 3.9+
- Docker and Docker Compose
- [k6](https://grafana.com/docs/k6/latest/set-up/install-k6/) (for running tests)

## Getting started

### 1. Start Keycloak

The included `compose.yml` starts PostgreSQL and Keycloak 26.5.5 with a pre-configured realm (`dpop-demo` client and `hakdogan` test user).

```bash
docker compose up -d
```

Wait until Keycloak is healthy:

```bash
docker compose ps
```

Keycloak will be available at `http://localhost:8080`. Admin credentials: `admin` / `admin`.

### 2. Start the Quarkus application

```bash
./mvnw quarkus:dev
```

The application starts on port `8180`.

### 3. Run the k6 tests

```bash
k6 run k6/dpop-test.js
```

The script runs 6 scenarios against the Quarkus API and prints the status and response body for each:

| # | Scenario | Expected |
|---|----------|----------|
| 1 | GET /user-info (Happy Path) | 200 |
| 2 | POST /user-info | 200 |
| 3 | POST /list-users | 200 |
| 4 | Replay Attack (jti reuse) | 401 |
| 5 | Method Mismatch (htm) | 401 |
| 6 | URL Mismatch (htu) | 401 |

All configuration values (Keycloak URL, client ID, credentials) can be overridden via environment variables:

```bash
k6 run -e KEYCLOAK_URL=http://keycloak:8080 -e CLIENT_ID=my-client -e USERNAME=user1 -e PASSWORD=secret k6/dpop-test.js
```

## Project structure

```
├── compose.yml                          # Keycloak + PostgreSQL
├── keycloak/
│   └── master-realm.json                # Pre-configured realm export
├── k6/
│   └── dpop-test.js                     # k6 test script
└── src/main/java/org/jugistanbul/
    ├── resource/
    │   └── ProtectedResource.java       # REST endpoints (GET/POST /user-info, POST /list-users)
    └── filter/
        └── DpopJtiFilter.java           # jti replay protection filter
```

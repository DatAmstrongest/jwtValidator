# jwtValidator

API with one endpoint that validates a JWT from the `Authorization` header.

A valid token uses the **RS256** algorithm. Its header must include `typ: JWT` and an `x5u` parameter: the URL of the PEM-encoded X.509 certificate used to verify the signature. The endpoint also checks the issue time (`iat`) and expiration (`exp`).

## Run

A published image is on Docker Hub: [kocmetehan/enable-banking-assignment](https://hub.docker.com/repository/docker/kocmetehan/enable-banking-assignment). No local build is required.

```bash
docker pull kocmetehan/enable-banking-assignment
docker run -p 80:80 kocmetehan/enable-banking-assignment
```

To run from source instead, Java 26 is required:

```bash
mvn spring-boot:run
```

The server listens on port 80, so the base URL is `http://localhost`.

On startup the app generates a mock RSA certificate and serves it at `GET http://localhost/api/mock/certs`. Use that URL as `x5u` when trying the endpoint locally.

`createJWT.py` signs a token with the mock private key written to `src/main/resources/certs/mock-key.pem`. It asks for the algorithm, token type, certificate URL, subject, name, issue time, and expiration, then prints the JWT. Press Enter at each prompt to accept the default.

```bash
pip install -r requirements.txt
python createJWT.py
```

This script only works after `mvn spring-boot:run`. A Docker deployment keeps the private key in memory and does not write `mock-key.pem`, so `createJWT.py` cannot sign a token for that deployment.

## Request

```http
GET /auth HTTP/1.1
Host: localhost
Accept: application/json
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsIng1dSI6Imh0dHA6Ly9sb2NhbGhvc3QvYXBpL21vY2svY2VydHMifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE2MTM4ODQ0MDJ9.signature
```

`Authorization` is `Bearer` followed by a space and the JWT.

```bash
curl -s http://localhost/auth -H "Authorization: Bearer <token>"
```

## Responses

Valid token:

```json
{
  "valid": true
}
```

Invalid token. `message` describes the failure:

```json
{
  "valid": false,
  "message": "Token has expired."
}
```

Other failure messages include:

- `Authorization header must begin with 'Bearer '`
- `Invalid or missing token type. Expected 'JWT'.`
- `Invalid algorithm. Only RS256 is supported.`
- `Missing 'x5u' header parameter.`
- `Signature verification failed.`
- `Token issue time (iat) is invalid or in the future.`
- `Validation error: ...` for a malformed token or a certificate that could not be downloaded

Each client IP address is limited to 20 requests per minute. Above that limit the endpoint returns **429** with an empty body.

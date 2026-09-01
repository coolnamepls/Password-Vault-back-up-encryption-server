# Secure Password Vault Backup API

A small client-server application that allows a password manager to securely back up and retrieve an encrypted password vault.

The server stores only encrypted vault data and does not have access to the user's master password, private key, or encryption key. Vault encryption and decryption are performed entirely on the client side.

## Overview

The system consists of:

* `server.py` – FastAPI server responsible for registration, mocked email verification, authentication, vault storage and retrieval.
* `client.py` – Demonstration client responsible for key generation, vault encryption/decryption, request signing and communicating with the server.
* `test_security.py` – Tests invalid signatures, tampered requests and replay attacks.
* `test_workflow.py` – Tests the full registration, encryption, storage, retrieval and decryption workflow.
* `persistance_test.py` – Tests that encrypted vault data survives a server process restart.
* `vault.db` – SQLite database created by the server for persistent storage.

## Requirements

The project was developed using Python 3.11.

Main dependencies include:

* FastAPI
* Uvicorn
* HTTPX
* cryptography
* argon2-cffi
* pytest

Install the required packages with:

```bash
pip install -r requirements.txt
```

## Running the Application

### 1. Start the server

From the project directory:

```bash
python -m uvicorn server:app --reload
```

The API will run locally at:

```text
http://127.0.0.1:8000
```

FastAPI documentation is available at:

```text
http://127.0.0.1:8000/docs
```

### 2. Run the demonstration client

In another terminal:

```bash
python client.py
```

The demonstration client performs the complete workflow:

1. Generates the user's signing and encryption keys from an email and master password.
2. Registers the user's email and public key.
3. Performs mocked email verification.
4. Encrypts a sample password vault locally.
5. Signs and sends a store request.
6. Retrieves the encrypted vault from the server.
7. Decrypts the retrieved vault locally.

The server never receives the master password, private signing key, encryption key or decrypted vault.

## API Operations

### Register

`POST /register`

Associates an email address with the user's public Ed25519 key.

Registration itself is unsigned because the server does not yet have a public key associated with the user.

### Verify

`POST /verify`

Mocks email verification by marking a registered account as verified.

In a production implementation this would be replaced with an actual email verification mechanism.

### Store

`POST /store`

Stores or replaces the user's encrypted vault.

The request must contain a valid Ed25519 signature and a nonce greater than the user's previously accepted nonce.

### Retrieve

`POST /retrieve`

Returns the user's encrypted vault after successfully authenticating the signed request.

The server returns the encrypted data without attempting to decrypt it.

## Authenticated Request Format

Store and retrieve operations use the following JSON envelope:

```json
{
  "email": "test@example.com",
  "payload": "<base64>",
  "nonce": 123,
  "signature": "<base64>"
}
```

The payload itself is Base64-encoded JSON.

For example, a store payload contains:

```json
{
  "type": "store",
  "vault": "<base64 encrypted vault>"
}
```

A retrieve payload contains:

```json
{
  "type": "retrieve"
}
```

Before signing, the client constructs a deterministic JSON representation containing:

```text
email + payload + nonce
```

using sorted JSON keys and fixed separators.

The resulting bytes are signed using the user's Ed25519 private key.

The server reconstructs the same representation and verifies the signature using the public key stored during registration.

## Key Derivation

The user provides:

* email address
* master password

The email is hashed using SHA-256 and the first 16 bytes are used as a deterministic salt.

The master password and salt are passed through Argon2id to produce a 32-byte master seed.

Argon2id was selected because password hashing should deliberately be computationally and memory expensive, making password guessing attacks more costly than using a fast hash such as SHA-256 directly.

HKDF is then used to derive two independent keys from the master seed:

```text
Master password
      |
   Argon2id
      |
 Master seed
   /       \
HKDF       HKDF
"signing"  "encryption"
   |           |
Ed25519      AES-256
signing key  encryption key
```

Using different HKDF contexts provides key separation so the same cryptographic key is not reused for both authentication and encryption.

## Vault Encryption

Vault encryption is performed entirely by the client using AES-GCM.

A fresh random 12-byte AES-GCM nonce is generated for every encryption operation.

The client stores:

```text
AES nonce + ciphertext + authentication tag
```

as a Base64 string.

The AES nonce is included with the encrypted data because it is required during decryption and does not need to remain secret.

AES-GCM also provides integrity protection, meaning modification of the encrypted vault causes decryption to fail.

The server treats the resulting Base64 value as opaque data.

## Request Authentication

Authenticated requests are signed using Ed25519.

The client signs:

```text
email + payload + request nonce
```

The corresponding public key is stored by the server.

This allows the server to verify that:

* the request was created by someone possessing the private key;
* the email has not been changed;
* the payload has not been changed;
* the nonce has not been changed.

The private signing key never leaves the client.

## Replay Protection

Every authenticated request contains a nonce.

The client currently generates the nonce using:

```python
time.time_ns()
```

The server stores the latest successfully accepted nonce for each user.

A request is rejected when:

```text
request nonce <= stored nonce
```

Therefore, replaying an already accepted signed request results in an HTTP `409` response.

The request nonce is separate from the random AES-GCM encryption nonce. They serve different purposes:

* Request nonce – prevents replay of authenticated API requests.
* AES-GCM nonce – ensures safe and unique vault encryption.

## Persistent Storage

SQLite is used for server-side persistence.

The database stores:

* email
* public key
* verification status
* encrypted vault
* latest accepted request nonce

The database does not contain the user's:

* master password
* private signing key
* encryption key
* decrypted password vault

The database path can also be configured using the `VAULT_DB_NAME` environment variable. This is used by the persistence test to run against an isolated temporary database.

## Testing

### Security and workflow tests

With the normal server running:

```bash
pytest -s -v test_security.py test_workflow.py
```

The security tests verify that the server rejects:

* requests signed using an incorrect private key;
* requests where the payload has been modified after signing;
* replayed authenticated requests.

The workflow test verifies the complete client-server encryption and retrieval process.

### Persistence test

The persistence test manages its own server processes and temporary database, so the normal development server should be stopped first.

Run:

```bash
pytest -s -v persistance_test.py
```

The test:

1. starts a server;
2. registers and verifies a user;
3. stores an encrypted vault;
4. terminates the server process;
5. starts a new server process using the same database;
6. retrieves the vault;
7. decrypts it and verifies it matches the original.

This demonstrates that vault backups survive a server process restart.

## TLS

The local demonstration uses HTTP for simplicity.

A production deployment should expose the FastAPI application only through HTTPS, for example through a TLS-enabled reverse proxy, load balancer or cloud hosting platform.

TLS is still important even though the vault itself is encrypted because it protects API traffic and metadata against interception and manipulation while in transit.

## Design Decisions and Limitations

### Mocked email verification

The `/verify` endpoint directly marks an email as verified. This is intentionally a mock implementation for the exercise.

A production system should use a time-limited verification token delivered to the user's email address.

### Deterministic key recovery

Keys are deterministically derived from the user's email and master password so that the user can recover their vault without separately storing encryption keys.

Because the salt is deterministically derived from the email, an attacker who obtains the database could attempt offline password guesses and compare derived public keys against the stored public key. Argon2id makes these guesses deliberately expensive, but it cannot prevent them entirely.

A stronger production design could generate a random per-user salt and store it on the server. The client could retrieve this public salt using the user's email before deriving its keys.

### Nonce generation

`time.time_ns()` provides a simple way for the demonstration client to generate increasing request nonces without maintaining local state.

It assumes the client's system clock does not move backwards. A production protocol could instead use server-issued counters, challenges, or persistent client-side nonce state.

### Concurrent requests

The current nonce check and database update are sufficient for the scope of this exercise but are not designed for high-concurrency distributed deployment.

A production implementation should make nonce validation and updating atomic using appropriate database transactions or conditional updates.

### Password changes

The current implementation does not provide a password-change or key-rotation mechanism.

Changing the master password would produce new signing and encryption keys, so a production system would require a controlled vault re-encryption and public-key rotation process.

## Security Properties

The design aims to provide the following properties:

* The server cannot decrypt stored vaults.
* The master password never leaves the client.
* Private signing keys never leave the client.
* Encryption keys never leave the client.
* AES-GCM protects vault confidentiality and integrity.
* Ed25519 signatures authenticate store and retrieve requests.
* Signed nonces provide replay protection.
* SQLite provides persistent encrypted backup storage.

# Secure Secrets Vault

A local-first, Vault-style microservice for securely storing application secrets.
Secrets are encrypted at rest, protected by JWT authentication, and every access
is captured through audit logs.

This project is intentionally built without Docker or cloud dependencies to keep
it free, portable, and easy to reason about.

---

## Features


- User registration and login with JWT authentication
- Per-user secret isolation (users can only access their own secrets)
- Envelope encryption using AES-GCM
- Encrypted secrets stored in a local SQLite database
- Audit logging for secret CREATE and READ operations
- Local-first and cost-free setup

---

## Tech Stack

- **Backend:** FastAPI
- **Auth:** JWT (PyJWT)
- **ORM:** SQLAlchemy
- **Database:** SQLite
- **Encryption:** AES-GCM (cryptography)
- **Password Hashing:** bcrypt (passlib)

---

## API Endpoints

### Authentication
- `POST /auth/register`
- `POST /auth/login`
- `GET /me`

### Secrets
- `POST /secrets`
- `GET /secrets/{secret_id}`

### Audit Logs
- `GET /audit`

### Health
- `GET /health`

---

## Local Setup

### Clone the repository
```bash
git clone https://github.com/KavyaVarshini-Anburasu/secure-secrets-vault.git
cd secure-secrets-vault




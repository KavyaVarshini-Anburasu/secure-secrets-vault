from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, Depends, HTTPException, status, Request
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

from .db import Base, engine, get_db
from .models import User, Secret, AuditLog
from .auth import hash_password, verify_password, create_access_token
from .deps import get_current_user
from .crypto import encrypt_secret, decrypt_secret, EncryptedBlob
from .audit import log_event

app = FastAPI(title="Local Dev Vault", version="0.1.0")

# Create tables on startup (simple for MVP)
Base.metadata.create_all(bind=engine)


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class CreateSecretRequest(BaseModel):
    name: str
    value: str


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/auth/register")
def register(payload: RegisterRequest, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == payload.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    user = User(email=payload.email, password_hash=hash_password(payload.password))
    db.add(user)
    db.commit()
    db.refresh(user)

    return {"message": "registered", "user_id": user.id}


@app.post("/auth/login")
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == payload.email).first()
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    token = create_access_token(subject=user.email)
    return {"access_token": token, "token_type": "bearer"}


@app.get("/me")
def me(user: User = Depends(get_current_user)):
    return {"id": user.id, "email": user.email}


@app.post("/secrets")
def create_secret(
    payload: CreateSecretRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    blob = encrypt_secret(payload.value)

    secret = Secret(
        owner_id=user.id,
        name=payload.name,
        ciphertext_b64=blob.ciphertext_b64,
        nonce_b64=blob.nonce_b64,
        enc_dek_b64=blob.enc_dek_b64,
        dek_nonce_b64=blob.dek_nonce_b64,
    )

    db.add(secret)
    db.commit()
    db.refresh(secret)

    # Audit log: create secret
    log_event(
        db=db,
        request=request,
        user=user,
        action="CREATE_SECRET",
        resource_type="secret",
        resource_id=secret.id,
    )

    return {"id": secret.id, "name": secret.name}


@app.get("/secrets/{secret_id}")
def get_secret(
    secret_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    secret = (
        db.query(Secret)
        .filter(Secret.id == secret_id, Secret.owner_id == user.id)
        .first()
    )

    if not secret:
        raise HTTPException(status_code=404, detail="Secret not found")

    # Audit log: read secret (log that access happened)
    log_event(
        db=db,
        request=request,
        user=user,
        action="READ_SECRET",
        resource_type="secret",
        resource_id=secret.id,
    )

    blob = EncryptedBlob(
        ciphertext_b64=secret.ciphertext_b64,
        nonce_b64=secret.nonce_b64,
        enc_dek_b64=secret.enc_dek_b64,
        dek_nonce_b64=secret.dek_nonce_b64,
    )

    value = decrypt_secret(blob)
    return {"id": secret.id, "name": secret.name, "value": value}


@app.get("/audit")
def my_audit_logs(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    logs = (
        db.query(AuditLog)
        .filter(AuditLog.user_id == user.id)
        .order_by(AuditLog.id.desc())
        .limit(50)
        .all()
    )

    return [
        {
            "id": l.id,
            "action": l.action,
            "resource_type": l.resource_type,
            "resource_id": l.resource_id,
            "ip": l.ip,
            "user_agent": l.user_agent,
            "created_at": str(l.created_at),
        }
        for l in logs
    ]

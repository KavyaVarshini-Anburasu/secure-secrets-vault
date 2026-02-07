from sqlalchemy import Column, Integer, String, DateTime, func
from .db import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

from sqlalchemy import ForeignKey, Text
from sqlalchemy.orm import relationship

class Secret(Base):
    __tablename__ = "secrets"

    id = Column(Integer, primary_key=True, index=True)
    owner_id = Column(Integer, ForeignKey("users.id"), index=True, nullable=False)

    name = Column(String, index=True, nullable=False)

    ciphertext_b64 = Column(Text, nullable=False)
    nonce_b64 = Column(String, nullable=False)
    enc_dek_b64 = Column(Text, nullable=False)
    dek_nonce_b64 = Column(String, nullable=False)

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)

    user_id = Column(Integer, ForeignKey("users.id"), index=True, nullable=False)
    action = Column(String, index=True, nullable=False)  # CREATE_SECRET, READ_SECRET, etc.
    resource_type = Column(String, index=True, nullable=False)  # "secret"
    resource_id = Column(Integer, index=True, nullable=True)

    ip = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

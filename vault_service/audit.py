from typing import Optional
from fastapi import Request
from sqlalchemy.orm import Session

from .models import AuditLog, User

def log_event(
    *,
    db: Session,
    request: Request,
    user: User,
    action: str,
    resource_type: str,
    resource_id: Optional[int] = None,
) -> None:
    ip = request.client.host if request.client else None
    ua = request.headers.get("user-agent")

    event = AuditLog(
        user_id=user.id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        ip=ip,
        user_agent=ua,
    )
    db.add(event)
    db.commit()

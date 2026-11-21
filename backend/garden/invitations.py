import hashlib
import sqlite3
import time
from typing import Annotated, NamedTuple

from fastapi import HTTPException
from pydantic import Field


InviteToken = Annotated[str, Field(min_length=40, max_length=100, pattern=r"^[a-zA-Z0-9_-]+$")]


class Invitation(NamedTuple):
    member_id: str
    project_id: str
    project_name: str
    email: str
    account_id: str | None


def find_invitation(db: sqlite3.Connection, token: str) -> Invitation:
    row = db.execute("""SELECT m.id,m.project_id,p.name,m.email,m.account_id
        FROM project_members m JOIN projects p ON p.id=m.project_id
        WHERE m.token_hash=? AND (m.account_id IS NOT NULL OR m.expires_at>?)""",
        (hashlib.sha256(token.encode()).hexdigest(), int(time.time()))).fetchone()
    if row is None:
        raise HTTPException(404, "Ссылка больше не действует. Попросите владельца проекта прислать новую.")
    return Invitation(*row)
